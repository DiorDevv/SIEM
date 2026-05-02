import asyncio
import json
import logging
import logging.config
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

import redis.asyncio as aioredis
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, update, text

from config import settings
from database import init_db, AsyncSessionLocal
from models.agent import Agent, AgentStatus
from models.user import User, UserRole
from models.rule import Rule, RuleSeverity
from models.active_response import ARPolicy, ARActionType, ARTriggerOn
from routes.auth import hash_password
from routes.auth import router as auth_router
from routes.agents import router as agents_router
from routes.logs import router as logs_router
from routes.alerts import router as alerts_router
from routes.rules import router as rules_router
from routes.dashboard import router as dashboard_router
from routes.active_response  import router as ar_router
from routes.vulnerabilities  import router as vulns_router
from routes.sca              import router as sca_router
from routes.reports          import router as reports_router
from routes.users            import router as users_router
from routes.audit            import router as audit_router
from routes.installer        import router as installer_router
from routes.totp             import router as totp_router
from routes.system_config    import router as system_config_router
from routes.inventory        import router as inventory_router
from routes.notifications    import router as notifications_router
from routes.cases            import router as cases_router
from routes.threat_intel     import router as threat_intel_router
from routes.correlation      import router as correlation_router
from services.elasticsearch_service import setup_index_template, get_es_client
from services.websocket_manager import ws_manager
from services.notification_service import notify_agent_offline
from middleware.rate_limit import RateLimitMiddleware
from middleware.request_id import RequestIDMiddleware


# ── Structured JSON logging setup ────────────────────────────────────────────

class _JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level":     record.levelname,
            "logger":    record.name,
            "message":   record.getMessage(),
        }
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry)


def _setup_logging():
    handler = logging.StreamHandler()
    handler.setFormatter(_JSONFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)
    # Quieten noisy third-party loggers
    for noisy in ("uvicorn.access", "httpx", "elasticsearch", "aiohttp"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


_setup_logging()
logger = logging.getLogger(__name__)


DEFAULT_RULES = [
    # ── Authentication ────────────────────────────────────────────────────────
    {
        "name": "Failed SSH Login",
        "description": "Detects failed SSH login attempts",
        "pattern": r"Failed password|authentication failure",
        "severity": RuleSeverity.MEDIUM,
        "level": 5,
        "category": "authentication",
        "groups": "authentication,ssh,syslog",
        "cooldown_seconds": 60,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
    },
    {
        "name": "SSH Invalid User",
        "description": "Login attempt with non-existent username",
        "pattern": r"Invalid user \S+ from",
        "severity": RuleSeverity.MEDIUM,
        "level": 6,
        "category": "authentication",
        "groups": "authentication,ssh,invalid_user",
        "cooldown_seconds": 30,
        "mitre_tactic": "Reconnaissance",
        "mitre_technique": "T1592",
    },
    {
        "name": "Successful Root Login",
        "description": "Detects successful SSH login as root",
        "pattern": r"Accepted\s+\w+\s+for\s+root",
        "severity": RuleSeverity.HIGH,
        "level": 10,
        "category": "authentication",
        "groups": "authentication,ssh,root_access",
        "cooldown_seconds": 300,
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1078",
    },
    {
        "name": "PAM Authentication Failure",
        "description": "PAM module reported authentication failure",
        "pattern": r"pam_unix.*authentication failure|pam_faillock.*fail",
        "severity": RuleSeverity.MEDIUM,
        "level": 5,
        "category": "authentication",
        "groups": "authentication,pam",
        "cooldown_seconds": 60,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
    },
    {
        "name": "Account Locked Out",
        "description": "User account locked after repeated failures",
        "pattern": r"pam_faillock.*user .* fail|account.*locked",
        "severity": RuleSeverity.HIGH,
        "level": 10,
        "category": "authentication",
        "groups": "authentication,account_lockout",
        "cooldown_seconds": 300,
        "mitre_tactic": "Impact",
        "mitre_technique": "T1531",
    },
    # ── Privilege Escalation ──────────────────────────────────────────────────
    {
        "name": "Sudo Command Used",
        "description": "Detects sudo command execution",
        "pattern": r"sudo:.*COMMAND=",
        "severity": RuleSeverity.LOW,
        "level": 3,
        "category": "privilege_escalation",
        "groups": "privilege_escalation,sudo",
        "cooldown_seconds": 120,
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1548.003",
    },
    {
        "name": "Sudo Authentication Failure",
        "description": "Failed sudo authentication attempt",
        "pattern": r"sudo:.*authentication failure|sudo:.*incorrect password",
        "severity": RuleSeverity.MEDIUM,
        "level": 6,
        "category": "privilege_escalation",
        "groups": "privilege_escalation,sudo",
        "cooldown_seconds": 60,
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1548.003",
    },
    {
        "name": "New User Created",
        "description": "A new local user account was created",
        "pattern": r"useradd|adduser|new user:|user_created",
        "severity": RuleSeverity.HIGH,
        "level": 8,
        "category": "persistence",
        "groups": "account_management,persistence",
        "cooldown_seconds": 300,
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1136.001",
    },
    {
        "name": "User Added to Sudoers",
        "description": "User added to sudo/wheel group",
        "pattern": r"usermod.*-aG.*(sudo|wheel)|gpasswd.*-a.*(sudo|wheel)",
        "severity": RuleSeverity.CRITICAL,
        "level": 12,
        "category": "privilege_escalation",
        "groups": "privilege_escalation,account_management",
        "cooldown_seconds": 600,
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1548",
    },
    # ── Availability / Crashes ────────────────────────────────────────────────
    {
        "name": "Service Crashed",
        "description": "Detects service crash or segfault",
        "pattern": r"segfault|core dumped|killed process",
        "severity": RuleSeverity.HIGH,
        "level": 9,
        "category": "availability",
        "groups": "availability,crash",
        "cooldown_seconds": 300,
        "mitre_tactic": "Impact",
        "mitre_technique": "T1499",
    },
    {
        "name": "OOM Killer Triggered",
        "description": "Out-of-memory killer terminated a process",
        "pattern": r"Out of memory.*Kill process|oom.kill",
        "severity": RuleSeverity.HIGH,
        "level": 9,
        "category": "availability",
        "groups": "availability,oom",
        "cooldown_seconds": 300,
        "mitre_tactic": "Impact",
        "mitre_technique": "T1499",
    },
    # ── Network / Firewall ────────────────────────────────────────────────────
    {
        "name": "Firewall Blocked Connection",
        "description": "Detects firewall blocking a connection",
        "pattern": r"UFW BLOCK|iptables.*(?:DROP|REJECT)",
        "severity": RuleSeverity.LOW,
        "level": 3,
        "category": "network",
        "groups": "firewall,network",
        "cooldown_seconds": 120,
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1562.004",
    },
    {
        "name": "Port Scan Detected",
        "description": "Multiple connection attempts to different ports",
        "pattern": r"UFW BLOCK|iptables.*DROP",
        "severity": RuleSeverity.MEDIUM,
        "level": 6,
        "category": "network",
        "groups": "network,scanning",
        "cooldown_seconds": 300,
        "frequency": 10,
        "timeframe": 60,
        "mitre_tactic": "Reconnaissance",
        "mitre_technique": "T1046",
    },
    # ── File Integrity ────────────────────────────────────────────────────────
    {
        "name": "Critical File Modified",
        "description": "A monitored critical system file was modified",
        "pattern": r"FIM ALERT.*MODIFIED|fim_modified",
        "severity": RuleSeverity.CRITICAL,
        "level": 13,
        "category": "fim",
        "groups": "fim,integrity",
        "cooldown_seconds": 300,
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1070",
    },
    {
        "name": "Critical File Deleted",
        "description": "A monitored critical system file was deleted",
        "pattern": r"FIM ALERT.*DELETED|fim_deleted",
        "severity": RuleSeverity.CRITICAL,
        "level": 14,
        "category": "fim",
        "groups": "fim,integrity",
        "cooldown_seconds": 300,
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1070.004",
    },
    # ── Rootkit / Malware ─────────────────────────────────────────────────────
    {
        "name": "Rootkit Indicator Found",
        "description": "Rootcheck detected a rootkit indicator",
        "pattern": r"ROOTCHECK.*ROOTKIT|rootkit_detected|ROOTCHECK.*CRITICAL",
        "severity": RuleSeverity.CRITICAL,
        "level": 15,
        "category": "rootcheck",
        "groups": "rootkit,malware",
        "cooldown_seconds": 3600,
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1014",
    },
    {
        "name": "Hidden Process Detected",
        "description": "A process visible in /proc but not in ps output",
        "pattern": r"Hidden process detected|hidden_process",
        "severity": RuleSeverity.CRITICAL,
        "level": 15,
        "category": "rootcheck",
        "groups": "rootkit,hidden_process",
        "cooldown_seconds": 1800,
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1014",
    },
    {
        "name": "LD_PRELOAD Hijack",
        "description": "/etc/ld.so.preload contains suspicious entries",
        "pattern": r"ld\.so\.preload|LD_PRELOAD.*hijack",
        "severity": RuleSeverity.CRITICAL,
        "level": 15,
        "category": "rootcheck",
        "groups": "rootkit,ld_preload",
        "cooldown_seconds": 3600,
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1574.006",
    },
    {
        "name": "Suspicious Process Execution",
        "description": "Process with reverse shell or attack tool pattern detected",
        "pattern": r"SUSPICIOUS process|suspicious_process|nc\s+-[le]|/dev/tcp|msfvenom",
        "severity": RuleSeverity.CRITICAL,
        "level": 14,
        "category": "malware",
        "groups": "process,attack,reverse_shell",
        "cooldown_seconds": 300,
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059",
    },
    # ── Docker / Container ────────────────────────────────────────────────────
    {
        "name": "Container OOM Killed",
        "description": "Docker container was killed by OOM",
        "pattern": r"container.*oom.kill|OOMKilled.*container",
        "severity": RuleSeverity.HIGH,
        "level": 9,
        "category": "docker",
        "groups": "docker,availability",
        "cooldown_seconds": 300,
        "mitre_tactic": "Impact",
        "mitre_technique": "T1499",
    },
    # ── System / Kernel ───────────────────────────────────────────────────────
    {
        "name": "Suspicious Kernel Module",
        "description": "A suspicious kernel module was loaded",
        "pattern": r"ROOTCHECK.*KERN_MODULE|suspicious kernel module|kernel_module_loaded",
        "severity": RuleSeverity.CRITICAL,
        "level": 14,
        "category": "rootcheck",
        "groups": "kernel,persistence",
        "cooldown_seconds": 3600,
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1547.006",
    },
    # ── Web / HTTP ────────────────────────────────────────────────────────────
    {
        "name": "Web Application Attack",
        "description": "SQL injection, XSS or path traversal attempt in HTTP request",
        "pattern": r"(?:union\s+select|<script>|\.\.\/\.\.\/|etc/passwd|cmd\.exe|powershell)",
        "severity": RuleSeverity.HIGH,
        "level": 10,
        "category": "web",
        "groups": "web,attack,injection",
        "cooldown_seconds": 120,
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190",
    },
    {
        "name": "HTTP Scanner Detected",
        "description": "Web scanner (nikto, sqlmap, dirbuster) detected",
        "pattern": r"nikto|sqlmap|dirbuster|gobuster|dirb|masscan|zgrab|nuclei",
        "severity": RuleSeverity.MEDIUM,
        "level": 7,
        "category": "web",
        "groups": "web,scanning,reconnaissance",
        "cooldown_seconds": 300,
        "mitre_tactic": "Reconnaissance",
        "mitre_technique": "T1595",
    },
    # ── Brute Force (built-in) ────────────────────────────────────────────────
    {
        "name": "Brute Force SSH Attack",
        "description": "5+ SSH failures in 60s from same IP",
        "pattern": None,
        "severity": RuleSeverity.CRITICAL,
        "level": 13,
        "category": "attack",
        "groups": "authentication,brute_force,ssh",
        "cooldown_seconds": 600,
        "custom_logic": "brute_force_ssh",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110.001",
    },
    # ── User Enumeration (built-in) ───────────────────────────────────────────
    {
        "name": "SSH User Enumeration",
        "description": "10+ invalid user attempts from same IP in 120s",
        "pattern": None,
        "severity": RuleSeverity.HIGH,
        "level": 11,
        "category": "reconnaissance",
        "groups": "ssh,reconnaissance,scanning",
        "cooldown_seconds": 600,
        "custom_logic": "user_enumeration",
        "mitre_tactic": "Reconnaissance",
        "mitre_technique": "T1592.001",
    },
    # ── Password Spray (built-in) ─────────────────────────────────────────────
    {
        "name": "Password Spray Attack",
        "description": "20+ auth failures from same IP in 300s (possible password spray)",
        "pattern": None,
        "severity": RuleSeverity.HIGH,
        "level": 12,
        "category": "attack",
        "groups": "authentication,brute_force,spray",
        "cooldown_seconds": 900,
        "custom_logic": "password_spray",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110.003",
    },
    # ── Root Login via SSH (built-in) ─────────────────────────────────────────
    {
        "name": "Root Login via SSH",
        "description": "Direct root login via SSH — should be disabled on hardened systems",
        "pattern": None,
        "severity": RuleSeverity.CRITICAL,
        "level": 14,
        "category": "authentication",
        "groups": "ssh,privilege_escalation,authentication",
        "cooldown_seconds": 300,
        "custom_logic": "root_login_ssh",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1078.003",
    },
    # ── AppArmor Denial ───────────────────────────────────────────────────────
    {
        "name": "AppArmor Access Denied",
        "description": "Process blocked by AppArmor mandatory access control",
        "pattern": r'apparmor="DENIED"',
        "severity": RuleSeverity.MEDIUM,
        "level": 7,
        "category": "integrity",
        "groups": "apparmor,integrity,access_control",
        "cooldown_seconds": 120,
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1562.001",
    },
    # ── Rootkit Detection ─────────────────────────────────────────────────────
    {
        "name": "Rootkit Indicator Detected",
        "description": "Rootcheck detected a rootkit, hidden process, or kernel module",
        "pattern": r"ROOTCHECK \[(?:ROOTKIT_FILE|HIDDEN_PROCESS|HIDDEN_FILE|KERNEL_MODULE)\]",
        "severity": RuleSeverity.CRITICAL,
        "level": 15,
        "category": "rootcheck",
        "groups": "rootcheck,malware,integrity",
        "cooldown_seconds": 60,
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1014",
    },
    # ── USB Connected ─────────────────────────────────────────────────────────
    {
        "name": "USB Device Connected",
        "description": "New USB storage device connected to the system",
        "pattern": r"new (?:high|full|low|super)-speed USB device|New USB device found",
        "severity": RuleSeverity.LOW,
        "level": 5,
        "category": "hardware",
        "groups": "usb,hardware,exfiltration",
        "cooldown_seconds": 60,
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1052.001",
    },
    # ── OOM Kill ──────────────────────────────────────────────────────────────
    {
        "name": "Out of Memory — Process Killed",
        "description": "Kernel OOM killer terminated a process due to memory exhaustion",
        "pattern": r"Out of memory: Kill process|oom_kill_process|memory cgroup out of memory",
        "severity": RuleSeverity.HIGH,
        "level": 10,
        "category": "availability",
        "groups": "kernel,oom,availability",
        "cooldown_seconds": 300,
        "mitre_tactic": "Impact",
        "mitre_technique": "T1499",
    },
    # ── Kernel Panic ──────────────────────────────────────────────────────────
    {
        "name": "Kernel Panic Detected",
        "description": "Kernel panic or BUG detected — system instability",
        "pattern": r"Kernel panic|BUG:|kernel BUG at|OOPS",
        "severity": RuleSeverity.CRITICAL,
        "level": 15,
        "category": "availability",
        "groups": "kernel,panic,availability",
        "cooldown_seconds": 60,
        "mitre_tactic": "Impact",
        "mitre_technique": "T1499",
    },
    # ── FIM: Critical System Files ────────────────────────────────────────────
    {
        "name": "Critical System File Modified",
        "description": "A critical system file was modified (passwd, sudoers, crontab, etc.)",
        "pattern": r"FIM \[(?:MODIFIED|CREATED|DELETED)\].*/(?:etc/passwd|etc/shadow|etc/sudoers|etc/crontab|etc/ssh/|root/\.ssh/)",
        "severity": RuleSeverity.CRITICAL,
        "level": 14,
        "category": "fim",
        "groups": "fim,integrity,persistence",
        "cooldown_seconds": 60,
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1098",
    },
]


DEFAULT_AR_POLICIES = [
    {
        "name":             "Block SSH Brute Force",
        "description":      "Auto-block source IP when SSH brute force rule fires",
        "trigger_on":       ARTriggerOn.rule_name,
        "trigger_rule":     "Brute Force SSH Attack",
        "action":           ARActionType.block_ip,
        "action_params":    {"unblock_after": 3600},
        "cooldown_seconds": 600,
    },
    {
        "name":             "Block Password Spray",
        "description":      "Auto-block IP performing password spray attacks",
        "trigger_on":       ARTriggerOn.rule_name,
        "trigger_rule":     "Password Spray Attack",
        "action":           ARActionType.block_ip,
        "action_params":    {"unblock_after": 7200},
        "cooldown_seconds": 900,
    },
    {
        "name":             "Email — CRITICAL Alerts",
        "description":      "Send email notification on CRITICAL severity alerts",
        "trigger_on":       ARTriggerOn.severity,
        "trigger_severity": "CRITICAL",
        "action":           ARActionType.email_alert,
        "action_params":    {"recipients": settings.DEFAULT_ADMIN_EMAIL},
        "cooldown_seconds": 300,
    },
]


async def seed_defaults():
    async with AsyncSessionLocal() as db:
        try:
            stmt = select(User).where(User.username == settings.DEFAULT_ADMIN_USERNAME)
            result = await db.execute(stmt)
            admin = result.scalar_one_or_none()
            if not admin:
                admin = User(
                    username=settings.DEFAULT_ADMIN_USERNAME,
                    email=settings.DEFAULT_ADMIN_EMAIL,
                    hashed_password=hash_password(settings.DEFAULT_ADMIN_PASSWORD),
                    role=UserRole.admin,
                    is_active=True,
                )
                db.add(admin)
                await db.flush()
                logger.info("Default admin user created")
        except Exception as e:
            await db.rollback()
            logger.warning(f"Admin seed skipped: {e}")

        try:
            for rule_data in DEFAULT_RULES:
                stmt = select(Rule).where(Rule.name == rule_data["name"])
                result = await db.execute(stmt)
                existing = result.scalar_one_or_none()
                if not existing:
                    rule = Rule(
                        name             = rule_data["name"],
                        description      = rule_data.get("description"),
                        pattern          = rule_data.get("pattern"),
                        severity         = rule_data["severity"],
                        level            = rule_data.get("level", 5),
                        category         = rule_data.get("category", "general"),
                        groups           = rule_data.get("groups"),
                        cooldown_seconds = rule_data.get("cooldown_seconds", 300),
                        enabled          = True,
                        custom_logic     = rule_data.get("custom_logic"),
                        frequency        = rule_data.get("frequency"),
                        timeframe        = rule_data.get("timeframe"),
                        mitre_tactic     = rule_data.get("mitre_tactic"),
                        mitre_technique  = rule_data.get("mitre_technique"),
                    )
                    db.add(rule)
            await db.commit()
            logger.info("Default rules seeded")
        except Exception as e:
            await db.rollback()
            logger.warning(f"Rules seed error: {e}")

        try:
            for ar_data in DEFAULT_AR_POLICIES:
                stmt = select(ARPolicy).where(ARPolicy.name == ar_data["name"])
                if not (await db.execute(stmt)).scalar_one_or_none():
                    db.add(ARPolicy(**ar_data))
            await db.commit()
            logger.info("Default AR policies seeded")
        except Exception as e:
            await db.rollback()
            logger.warning(f"AR policies seed error: {e}")


async def ar_timeout_checker():
    """Background task: mark stuck 'sent' executions as 'timeout', process auto-unblocks."""
    from engine.active_response import mark_timed_out_executions, process_auto_unblocks
    while True:
        await asyncio.sleep(120)   # every 2 minutes
        try:
            async with AsyncSessionLocal() as db:
                timed_out = await mark_timed_out_executions(db)
                unblocks   = await process_auto_unblocks(db)
                await db.commit()
                if timed_out:
                    logger.info(f"AR timeout checker: marked {timed_out} execution(s) as timeout")
                if unblocks:
                    logger.info(f"AR timeout checker: scheduled {unblocks} auto-unblock(s)")
        except Exception as e:
            logger.error(f"AR timeout checker error: {e}")


async def anomaly_baseline_syncer():
    """Background task: flush Redis anomaly baselines to PostgreSQL every 5 minutes."""
    from engine.anomaly_detector import sync_baselines_to_db, SYNC_INTERVAL
    while True:
        await asyncio.sleep(SYNC_INTERVAL)
        try:
            async with AsyncSessionLocal() as db:
                written = await sync_baselines_to_db(db)
                if written:
                    logger.info(f"Anomaly baselines synced: {written} metric(s) written to DB")
        except Exception as e:
            logger.error(f"Anomaly baseline sync error: {e}")


async def agent_status_checker():
    while True:
        await asyncio.sleep(settings.AGENT_STATUS_CHECK_INTERVAL)
        try:
            async with AsyncSessionLocal() as db:
                timeout_cutoff = datetime.utcnow() - timedelta(seconds=settings.AGENT_HEARTBEAT_TIMEOUT)
                stmt = select(Agent).where(
                    Agent.is_active == True,
                    Agent.status == AgentStatus.online,
                    Agent.last_seen < timeout_cutoff,
                )
                result = await db.execute(stmt)
                agents_to_offline = result.scalars().all()
                for agent in agents_to_offline:
                    agent.status = AgentStatus.offline
                    logger.info(f"Agent {agent.hostname} marked offline")
                    await notify_agent_offline(agent.agent_id, agent.hostname)
                await db.commit()
        except Exception as e:
            logger.error(f"Agent status checker error: {e}")


_checker_task       = None
_ar_timeout_task      = None
_anomaly_sync_task    = None
_correlation_task     = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _checker_task, _ar_timeout_task, _anomaly_sync_task, _correlation_task
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")

    await init_db()
    logger.info("Database initialized")

    try:
        await setup_index_template()
    except Exception as e:
        logger.warning(f"ES setup failed (will retry on demand): {e}")

    await seed_defaults()

    # Restore anomaly baselines from PostgreSQL → Redis on startup
    try:
        from engine.anomaly_detector import load_baselines_from_db
        async with AsyncSessionLocal() as db:
            loaded = await load_baselines_from_db(db)
            logger.info(f"Anomaly baselines restored: {loaded} metric(s) loaded from DB into Redis")
    except Exception as e:
        logger.warning(f"Anomaly baseline restore skipped: {e}")

    # Seed default correlation rules
    try:
        from routes.correlation import seed_default_correlation_rules
        async with AsyncSessionLocal() as db:
            await seed_default_correlation_rules(db)
            await db.commit()
            logger.info("Correlation rules seeded")
    except Exception as e:
        logger.warning(f"Correlation rules seed skipped: {e}")

    _checker_task      = asyncio.create_task(agent_status_checker())
    _ar_timeout_task   = asyncio.create_task(ar_timeout_checker())
    _anomaly_sync_task = asyncio.create_task(anomaly_baseline_syncer())

    # Correlation engine background evaluator
    try:
        from services.correlation_engine import correlation_evaluator
        _correlation_task = asyncio.create_task(correlation_evaluator())
        logger.info("Correlation engine started")
    except Exception as e:
        logger.warning(f"Correlation engine failed to start: {e}")

    yield

    for task in (_checker_task, _ar_timeout_task, _anomaly_sync_task, _correlation_task):
        if task:
            task.cancel()
    logger.info("SIEM backend shutting down")


app = FastAPI(
    title="SecureWatch SIEM API",
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/api/docs" if settings.DEBUG else None,   # Disable Swagger in prod
    redoc_url="/api/redoc" if settings.DEBUG else None,
)

# ── Middleware (order matters — outermost wraps first) ────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware, redis_url=settings.REDIS_URL)
app.add_middleware(RequestIDMiddleware)

# ── Prometheus metrics ────────────────────────────────────────────────────────
if settings.METRICS_ENABLED:
    try:
        from prometheus_fastapi_instrumentator import Instrumentator
        Instrumentator(
            should_group_status_codes=True,
            should_ignore_untemplated=True,
            should_respect_env_var=False,
            excluded_handlers=["/api/health", "/api/metrics"],
        ).instrument(app).expose(app, endpoint="/api/metrics", include_in_schema=False)
        logger.info("Prometheus metrics enabled at /api/metrics")
    except ImportError:
        logger.warning("prometheus-fastapi-instrumentator not installed, metrics disabled")

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(agents_router)
app.include_router(logs_router)
app.include_router(alerts_router)
app.include_router(rules_router)
app.include_router(dashboard_router)
app.include_router(ar_router)
app.include_router(vulns_router)
app.include_router(sca_router)
app.include_router(reports_router)
app.include_router(users_router)
app.include_router(audit_router)
app.include_router(installer_router)
app.include_router(totp_router)
app.include_router(system_config_router)
app.include_router(inventory_router)
app.include_router(notifications_router)
app.include_router(cases_router)
app.include_router(threat_intel_router)
app.include_router(correlation_router)


@app.get("/api/health", include_in_schema=False)
async def health():
    """Deep health check — verifies all backend dependencies."""
    checks: dict[str, str] = {}

    # PostgreSQL
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = f"error: {e}"

    # Elasticsearch
    try:
        es = get_es_client()
        info = await es.cluster.health(timeout="3s")
        checks["elasticsearch"] = info.get("status", "unknown")
    except Exception as e:
        checks["elasticsearch"] = f"error: {e}"

    # Redis
    try:
        r = aioredis.from_url(settings.REDIS_URL)
        await r.ping()
        await r.aclose()
        checks["redis"] = "ok"
    except Exception as e:
        checks["redis"] = f"error: {e}"

    ok_values = {"ok", "green", "yellow"}
    overall = "ok" if all(v in ok_values for v in checks.values()) else "degraded"
    status_code = 200 if overall == "ok" else 503

    from fastapi.responses import JSONResponse
    return JSONResponse(
        status_code=status_code,
        content={
            "status":    overall,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "version":   settings.APP_VERSION,
            "checks":    checks,
        },
    )


@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)
