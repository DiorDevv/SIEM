"""
Wazuh-style rule engine.

Pipeline per log:
  1. Decode → structured fields
  2. Threat intel enrichment
  3. Regex / field-value rules
  4. Frequency rules (sliding window)
  5. Composite / correlation patterns
  6. MITRE ATT&CK tagging
  7. Alert creation with dedup + cooldown
"""
import re
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from models.rule  import Rule
from models.alert import Alert, AlertStatus, AlertSeverity
from engine.decoder           import decode_log
from engine.correlation       import check_frequency, check_composite_patterns, record_event
from engine.mitre             import get_mitre_tags, level_to_severity, severity_to_level
from engine.threat_intel      import enrich_log, extract_ips_from_log
from engine.active_response   import trigger_active_response
from engine.anomaly_detector  import run_anomaly_checks
from services.notification_service import notify_new_alert, notify_alert_channels

logger = logging.getLogger(__name__)


# ── Field-value evaluator ─────────────────────────────────────────────────────

def _eval_field(rule: Rule, parsed: dict) -> bool:
    """Check rule.field_name / field_value condition against decoded fields."""
    if not rule.field_name:
        return True
    val = parsed.get(rule.field_name)
    if val is None:
        return False
    cond = rule.field_value or ""

    # Numeric comparison: ">=400", "==200", "<500"
    m = re.match(r'^([><=!]+)\s*(\d+(?:\.\d+)?)$', cond)
    if m:
        try:
            num_val = float(val)
            num_cond = float(m.group(2))
            op = m.group(1)
            return {
                ">":  num_val >  num_cond,
                ">=": num_val >= num_cond,
                "<":  num_val <  num_cond,
                "<=": num_val <= num_cond,
                "==": num_val == num_cond,
                "!=": num_val != num_cond,
            }.get(op, False)
        except (ValueError, TypeError):
            return False

    # Regex match — validate pattern first to prevent ReDoS
    if cond.startswith("~"):
        pattern = cond[1:]
        try:
            return bool(re.search(pattern, str(val), re.I))
        except re.error:
            logger.warning("Invalid regex pattern in rule, skipping: %r", pattern)
            return False

    # Exact match
    return str(val).lower() == cond.lower()


# ── Core alert factory (aggregation + cooldown) ───────────────────────────────

async def _upsert_alert(
    db:            AsyncSession,
    *,
    agent_id:      str,
    agent_hostname: str,
    title:         str,
    description:   str,
    severity:      str,
    level:         int,
    agg_key:       str,
    rule_id:       Optional[int]  = None,
    rule_name:     Optional[str]  = None,
    groups:        Optional[str]  = None,
    category:      Optional[str]  = None,
    mitre_tactic:  Optional[str]  = None,
    mitre_tech:    Optional[str]  = None,
    src_ip:        Optional[str]  = None,
    threat_info:   Optional[dict] = None,
    raw_log:       Optional[str]  = None,
    parsed_fields: Optional[dict] = None,
    log_id:        Optional[str]  = None,
    cooldown_seconds: int = 3600,
) -> Optional[Alert]:
    """
    Aggregation-aware alert creation:
      • If an open/investigating alert with the same agg_key exists within 24 h
        → increment event_count and last_seen_at (no new row).
      • Else if any alert with this agg_key was created within cooldown_seconds
        → suppress (avoid re-opening a just-closed alert).
      • Otherwise → create new alert.
    Returns the alert (new or aggregated) or None if suppressed.
    """
    now = datetime.now(timezone.utc)

    # ── 1. Aggregate into existing open/investigating alert ───────────────────
    agg_cutoff = now - timedelta(hours=24)
    existing = (await db.execute(
        select(Alert).where(
            and_(
                Alert.agg_key == agg_key,
                Alert.status.in_([AlertStatus.open, AlertStatus.investigating]),
                Alert.first_seen_at >= agg_cutoff,
            )
        ).limit(1)
    )).scalar_one_or_none()

    if existing:
        existing.event_count += 1
        existing.last_seen_at = now
        existing.updated_at   = now
        if threat_info and threat_info.get("malicious") and existing.level < 13:
            existing.level    += 1
            existing.severity  = level_to_severity(existing.level)
        await db.flush()
        return existing

    # ── 2. Cooldown: suppress if created recently (prevents re-flood after close) ─
    if cooldown_seconds > 0:
        cooldown_cutoff = now - timedelta(seconds=cooldown_seconds)
        if (await db.execute(
            select(Alert.id).where(
                and_(Alert.agg_key == agg_key, Alert.created_at >= cooldown_cutoff)
            ).limit(1)
        )).scalar_one_or_none():
            return None

    # ── 3. Create new alert ───────────────────────────────────────────────────
    alert = Alert(
        rule_id         = rule_id,
        agent_id        = agent_id,
        severity        = severity,
        level           = level,
        title           = title,
        description     = description,
        log_id          = str(log_id) if log_id else None,
        status          = AlertStatus.open,
        agent_hostname  = agent_hostname,
        rule_name       = rule_name,
        groups          = groups,
        category        = category,
        mitre_tactic    = mitre_tactic,
        mitre_technique = mitre_tech,
        src_ip          = src_ip,
        threat_intel    = threat_info,
        raw_log         = (raw_log or "")[:4096],
        parsed_fields   = parsed_fields,
        agg_key         = agg_key,
        event_count     = 1,
        first_seen_at   = now,
        last_seen_at    = now,
    )
    db.add(alert)
    await db.flush()
    await db.refresh(alert)

    logger.info("Alert id=%s title='%s' severity=%s", alert.id, alert.title, alert.severity)

    await notify_new_alert({
        "id":              alert.id,
        "severity":        alert.severity,
        "level":           alert.level,
        "title":           alert.title,
        "description":     alert.description,
        "agent_hostname":  alert.agent_hostname,
        "rule_name":       alert.rule_name,
        "status":          alert.status,
        "mitre_tactic":    alert.mitre_tactic,
        "mitre_technique": alert.mitre_technique,
        "src_ip":          alert.src_ip,
        "event_count":     1,
        "created_at":      str(alert.created_at),
    })

    try:
        await trigger_active_response(db, alert)
    except Exception as exc:
        logger.error("Active response trigger failed: %s", exc, exc_info=True)

    # Enrich alert with IOC database matches
    try:
        from services.threat_intel_service import enrich_alert_with_ti
        ti_hits = await enrich_alert_with_ti(db, alert)
        if ti_hits:
            existing_ti = alert.threat_intel or []
            if isinstance(existing_ti, list):
                alert.threat_intel = existing_ti + ti_hits
            else:
                alert.threat_intel = ti_hits
    except Exception as exc:
        logger.debug("TI enrichment failed: %s", exc)

    await notify_alert_channels(db, alert)

    return alert


async def _create_alert(
    db:            AsyncSession,
    rule:          Rule,
    agent_id:      str,
    agent_hostname: str,
    description:   str,
    log_id:        Optional[str],
    raw_log:       Optional[str],
    parsed_fields: dict,
    src_ip:        Optional[str]  = None,
    threat_info:   Optional[dict] = None,
    mitre_tactic:  Optional[str]  = None,
    mitre_tech:    Optional[str]  = None,
    override_severity: Optional[str] = None,
    override_level:    Optional[int] = None,
) -> Optional[Alert]:
    severity = override_severity or rule.severity
    level    = override_level    or rule.level
    if threat_info and threat_info.get("malicious") and level < 12:
        level    += 2
        severity  = level_to_severity(level)

    agg_key = hashlib.sha256(f"{rule.id}:{agent_id}:{src_ip or ''}".encode()).hexdigest()[:32]

    return await _upsert_alert(
        db,
        agent_id       = agent_id,
        agent_hostname = agent_hostname,
        title          = rule.name,
        description    = description,
        severity       = severity,
        level          = level,
        agg_key        = agg_key,
        rule_id        = rule.id,
        rule_name      = rule.name,
        groups         = rule.groups,
        category       = rule.category,
        mitre_tactic   = mitre_tactic or rule.mitre_tactic,
        mitre_tech     = mitre_tech   or rule.mitre_technique,
        src_ip         = src_ip,
        threat_info    = threat_info,
        raw_log        = raw_log,
        parsed_fields  = parsed_fields,
        log_id         = log_id,
        cooldown_seconds = rule.cooldown_seconds,
    )


# ── Main pipeline ─────────────────────────────────────────────────────────────

async def run_rules_against_logs(
    db:             AsyncSession,
    logs:           List[Dict[str, Any]],
    agent_id:       str,
    agent_hostname: str,
):
    if not logs:
        return

    # Load enabled rules once
    stmt = select(Rule).where(Rule.enabled == True)
    rules: List[Rule] = (await db.execute(stmt)).scalars().all()

    regex_rules    = [r for r in rules if r.pattern and not r.custom_logic and not r.frequency]
    freq_rules     = [r for r in rules if r.pattern and r.frequency and r.timeframe]
    brute_rule     = next((r for r in rules if r.custom_logic == "brute_force_ssh"), None)
    enum_rule      = next((r for r in rules if r.custom_logic == "user_enumeration"), None)
    spray_rule     = next((r for r in rules if r.custom_logic == "password_spray"), None)
    rootlogin_rule = next((r for r in rules if r.custom_logic == "root_login_ssh"), None)

    alerts_created = 0

    for log in logs:
        # ── 1. Decode ────────────────────────────────────────────────────────
        parsed = decode_log(log)
        log    = {**log, "parsed_fields": parsed}

        # ── 2. Threat intel ──────────────────────────────────────────────────
        log    = await enrich_log(log)
        parsed = log.get("parsed_fields", {}) or {}

        message  = log.get("message", "") or ""
        raw      = log.get("raw", message)
        text     = f"{message} {raw}"
        log_id   = log.get("id") or log.get("es_id")
        src_ip   = parsed.get("src_ip") or parsed.get("ssh_src_ip") or parsed.get("client_ip")
        ti_list  = parsed.get("threat_intel", [])
        ti_info  = ti_list[0] if ti_list else None
        # Prefer decoder's "event" field; fall back to log_parser's "event_type"
        event_type = parsed.get("event") or parsed.get("event_type")

        # ── 3. Regex rules ───────────────────────────────────────────────────
        for rule in regex_rules:
            try:
                if not re.search(rule.pattern, text, re.IGNORECASE):
                    continue
                if not _eval_field(rule, parsed):
                    continue

                tactic, tech = get_mitre_tags(
                    event_type=event_type,
                    category=rule.category,
                    rule_mitre_tactic=rule.mitre_tactic,
                    rule_mitre_technique=rule.mitre_technique,
                )
                a = await _create_alert(
                    db, rule, agent_id, agent_hostname,
                    description  = f"Rule '{rule.name}' matched: {message[:400]}",
                    log_id       = log_id,
                    raw_log      = raw,
                    parsed_fields= parsed,
                    src_ip       = src_ip,
                    threat_info  = ti_info,
                    mitre_tactic = tactic,
                    mitre_tech   = tech,
                )
                if a:
                    alerts_created += 1
            except Exception as e:
                logger.error(f"Regex rule {rule.id} error: {e}", exc_info=True)

        # ── 4. Frequency rules ───────────────────────────────────────────────
        for rule in freq_rules:
            try:
                if not re.search(rule.pattern, text, re.IGNORECASE):
                    continue

                groupby = src_ip or agent_id
                triggered, count = await check_frequency(
                    rule.id, agent_id, groupby,
                    rule.frequency, rule.timeframe,
                )
                if not triggered:
                    continue

                tactic, tech = get_mitre_tags(
                    event_type=event_type,
                    category=rule.category,
                    rule_mitre_tactic=rule.mitre_tactic,
                    rule_mitre_technique=rule.mitre_technique,
                )
                a = await _create_alert(
                    db, rule, agent_id, agent_hostname,
                    description  = (
                        f"Frequency rule triggered: {count} events in "
                        f"{rule.timeframe}s from {groupby} — {message[:300]}"
                    ),
                    log_id       = log_id,
                    raw_log      = raw,
                    parsed_fields= parsed,
                    src_ip       = src_ip,
                    threat_info  = ti_info,
                    mitre_tactic = tactic,
                    mitre_tech   = tech,
                )
                if a:
                    alerts_created += 1
            except Exception as e:
                logger.error(f"Freq rule {rule.id} error: {e}", exc_info=True)

        # ── 5. Built-in behavioral detections ────────────────────────────────

        event_type_pf = parsed.get("event_type", "")

        # 5a. Brute force SSH (≥5 failures from same IP in 60s)
        if brute_rule and src_ip:
            is_fail = bool(re.search(
                r"Failed password|authentication failure|Invalid user|ssh_failed",
                text, re.IGNORECASE
            ))
            if is_fail:
                triggered, count = await check_frequency(
                    brute_rule.id, agent_id, src_ip, 5, 60
                )
                if triggered:
                    a = await _create_alert(
                        db, brute_rule, agent_id, agent_hostname,
                        description  = (
                            f"SSH brute force: {count} failures in 60s from {src_ip}"
                        ),
                        log_id       = log_id,
                        raw_log      = raw,
                        parsed_fields= parsed,
                        src_ip       = src_ip,
                        threat_info  = ti_info,
                        mitre_tactic = "Credential Access",
                        mitre_tech   = "T1110.001",
                    )
                    if a:
                        alerts_created += 1

        # 5b. User enumeration (≥10 "Invalid user" from same IP in 120s)
        if enum_rule and src_ip and event_type_pf == "ssh_invalid_user":
            triggered, count = await check_frequency(
                enum_rule.id, agent_id, src_ip, 10, 120
            )
            if triggered:
                a = await _create_alert(
                    db, enum_rule, agent_id, agent_hostname,
                    description  = (
                        f"User enumeration: {count} invalid users from {src_ip} in 120s"
                    ),
                    log_id       = log_id,
                    raw_log      = raw,
                    parsed_fields= parsed,
                    src_ip       = src_ip,
                    threat_info  = ti_info,
                    mitre_tactic = "Reconnaissance",
                    mitre_tech   = "T1592.001",
                )
                if a:
                    alerts_created += 1

        # 5c. Password spray (≥20 auth failures across different users from same IP in 300s)
        if spray_rule and src_ip:
            is_auth_fail = event_type_pf in (
                "ssh_failed", "authentication_failed", "pam_auth_failed"
            )
            if is_auth_fail:
                triggered, count = await check_frequency(
                    spray_rule.id, agent_id, src_ip, 20, 300
                )
                if triggered:
                    a = await _create_alert(
                        db, spray_rule, agent_id, agent_hostname,
                        description  = (
                            f"Password spray detected: {count} auth failures from "
                            f"{src_ip} in 300s"
                        ),
                        log_id       = log_id,
                        raw_log      = raw,
                        parsed_fields= parsed,
                        src_ip       = src_ip,
                        threat_info  = ti_info,
                        mitre_tactic = "Credential Access",
                        mitre_tech   = "T1110.003",
                    )
                    if a:
                        alerts_created += 1

        # 5d. Root login via SSH (always alert — should never happen in hardened systems)
        if rootlogin_rule and parsed.get("is_root_login"):
            a = await _create_alert(
                db, rootlogin_rule, agent_id, agent_hostname,
                description  = (
                    f"Root login via SSH from {src_ip or 'unknown'}"
                ),
                log_id       = log_id,
                raw_log      = raw,
                parsed_fields= parsed,
                src_ip       = src_ip,
                threat_info  = ti_info,
                mitre_tactic = "Privilege Escalation",
                mitre_tech   = "T1078.003",
            )
            if a:
                alerts_created += 1

        # ── 6. Anomaly detection (statistical baseline checks) ───────────────
        try:
            anomalies = await run_anomaly_checks(agent_id, event_type, parsed)
            for anomaly in anomalies:
                a = await _upsert_alert(
                    db,
                    agent_id       = agent_id,
                    agent_hostname = agent_hostname,
                    title          = f"Anomaly: {anomaly.metric_key}",
                    description    = anomaly.description,
                    severity       = anomaly.severity,
                    level          = anomaly.level,
                    agg_key        = hashlib.sha256(f"anomaly:{agent_id}:{anomaly.metric_key}".encode()).hexdigest()[:32],
                    rule_name      = f"Anomaly Detector [{anomaly.metric_key}]",
                    category       = "anomaly",
                    groups         = "anomaly,statistical,behavioral",
                    mitre_tactic   = anomaly.mitre_tactic,
                    mitre_tech     = anomaly.mitre_tech,
                    src_ip         = src_ip,
                    parsed_fields  = {
                        **parsed,
                        "anomaly_z_score":       anomaly.z_score,
                        "anomaly_confidence":    anomaly.confidence,
                        "anomaly_metric":        anomaly.metric_key,
                        "anomaly_current":       anomaly.current_value,
                        "anomaly_baseline_mean": anomaly.baseline_mean,
                        "anomaly_baseline_std":  anomaly.baseline_std,
                        "anomaly_samples":       anomaly.sample_count,
                    },
                    cooldown_seconds = 3600,
                )
                if a:
                    alerts_created += 1
        except Exception as exc:
            logger.error("Anomaly detection error: %s", exc, exc_info=True)

        # ── 7. Composite / correlation patterns ──────────────────────────────
        if event_type:
            await record_event(agent_id, event_type, parsed)
            patterns = await check_composite_patterns(agent_id, event_type, parsed)

            for pattern in patterns:
                composite_rule = next(
                    (r for r in rules if r.name == pattern["name"]), None
                )
                if not composite_rule:
                    a = await _upsert_alert(
                        db,
                        agent_id       = agent_id,
                        agent_hostname = agent_hostname,
                        title          = pattern["name"],
                        description    = pattern["description"],
                        severity       = pattern["severity"],
                        level          = pattern["level"],
                        agg_key        = hashlib.sha256(f"composite:{agent_id}:{pattern['name']}:{src_ip or ''}".encode()).hexdigest()[:32],
                        rule_name      = pattern["name"],
                        category       = "correlation",
                        groups         = "correlation,composite",
                        mitre_tactic   = pattern.get("mitre_tactic"),
                        mitre_tech     = pattern.get("mitre_technique"),
                        src_ip         = src_ip,
                        parsed_fields  = parsed,
                        cooldown_seconds = 600,
                    )
                    if a:
                        alerts_created += 1

    if alerts_created:
        logger.info(f"Created {alerts_created} alerts for agent {agent_hostname}")
