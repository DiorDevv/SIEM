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
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from models.rule  import Rule
from models.alert import Alert, AlertStatus, AlertSeverity
from engine.decoder          import decode_log
from engine.correlation      import check_frequency, check_composite_patterns, record_event
from engine.mitre            import get_mitre_tags, level_to_severity, severity_to_level
from engine.threat_intel     import enrich_log, extract_ips_from_log
from engine.active_response  import trigger_active_response
from services.notification_service import notify_new_alert

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

    # Regex match
    if cond.startswith("~"):
        return bool(re.search(cond[1:], str(val), re.I))

    # Exact match
    return str(val).lower() == cond.lower()


# ── Alert factory ─────────────────────────────────────────────────────────────

async def _create_alert(
    db:            AsyncSession,
    rule:          Rule,
    agent_id:      str,
    agent_hostname: str,
    description:   str,
    log_id:        Optional[str],
    raw_log:       Optional[str],
    parsed_fields: dict,
    src_ip:        Optional[str] = None,
    threat_info:   Optional[dict] = None,
    mitre_tactic:  Optional[str] = None,
    mitre_tech:    Optional[str] = None,
    override_severity: Optional[str] = None,
    override_level:    Optional[int] = None,
) -> Optional[Alert]:

    # Cooldown check
    cutoff = datetime.utcnow() - timedelta(seconds=rule.cooldown_seconds)
    stmt = select(Alert).where(
        and_(
            Alert.rule_id == rule.id,
            Alert.agent_id == agent_id,
            Alert.created_at >= cutoff,
        )
    ).limit(1)
    if (await db.execute(stmt)).scalar_one_or_none():
        return None

    severity = override_severity or rule.severity
    level    = override_level    or rule.level

    # Escalate if malicious IP
    if threat_info and threat_info.get("malicious") and level < 12:
        level += 2
        severity = level_to_severity(level)

    alert = Alert(
        rule_id         = rule.id,
        agent_id        = agent_id,
        severity        = severity,
        level           = level,
        title           = rule.name,
        description     = description,
        log_id          = str(log_id) if log_id else None,
        status          = AlertStatus.open,
        agent_hostname  = agent_hostname,
        rule_name       = rule.name,
        groups          = rule.groups,
        category        = rule.category,
        mitre_tactic    = mitre_tactic or rule.mitre_tactic,
        mitre_technique = mitre_tech   or rule.mitre_technique,
        src_ip          = src_ip,
        threat_intel    = threat_info,
        raw_log         = (raw_log or "")[:4096],
        parsed_fields   = parsed_fields,
    )
    db.add(alert)
    await db.flush()
    logger.info(f"Flushed alert id={alert.id} title='{alert.title}' severity={alert.severity}")
    await db.refresh(alert)

    await notify_new_alert({
        "id":               alert.id,
        "severity":         alert.severity,
        "level":            alert.level,
        "title":            alert.title,
        "description":      alert.description,
        "agent_hostname":   alert.agent_hostname,
        "rule_name":        alert.rule_name,
        "status":           alert.status,
        "mitre_tactic":     alert.mitre_tactic,
        "mitre_technique":  alert.mitre_technique,
        "src_ip":           alert.src_ip,
        "created_at":       str(alert.created_at),
    })

    try:
        await trigger_active_response(db, alert)
    except Exception as e:
        logger.error(f"Active response trigger failed: {e}", exc_info=True)

    return alert


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
        event_type = parsed.get("event")

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

        # ── 5. Brute force (built-in freq logic) ─────────────────────────────
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
                            f"Brute force SSH detected: {count} failures in 60s "
                            f"from {src_ip}"
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

        # ── 6. Composite / correlation patterns ──────────────────────────────
        if event_type:
            await record_event(agent_id, event_type, parsed)
            patterns = await check_composite_patterns(agent_id, event_type, parsed)

            for pattern in patterns:
                # Find or use brute_rule as placeholder rule
                composite_rule = next(
                    (r for r in rules if r.name == pattern["name"]), None
                )
                if not composite_rule:
                    # Create a synthetic alert without a real rule_id
                    alert = Alert(
                        rule_id         = None,
                        agent_id        = agent_id,
                        severity        = pattern["severity"],
                        level           = pattern["level"],
                        title           = pattern["name"],
                        description     = pattern["description"],
                        status          = AlertStatus.open,
                        agent_hostname  = agent_hostname,
                        rule_name       = pattern["name"],
                        mitre_tactic    = pattern.get("mitre_tactic"),
                        mitre_technique = pattern.get("mitre_technique"),
                        category        = "correlation",
                        groups          = "correlation,composite",
                        src_ip          = src_ip,
                        parsed_fields   = parsed,
                    )
                    db.add(alert)
                    await db.flush()
                    await db.refresh(alert)
                    await notify_new_alert({
                        "id":              alert.id,
                        "severity":        alert.severity,
                        "level":           alert.level,
                        "title":           alert.title,
                        "description":     alert.description,
                        "agent_hostname":  agent_hostname,
                        "mitre_tactic":    alert.mitre_tactic,
                        "mitre_technique": alert.mitre_technique,
                        "created_at":      str(alert.created_at),
                    })
                    alerts_created += 1

    if alerts_created:
        logger.info(f"Created {alerts_created} alerts for agent {agent_hostname}")
