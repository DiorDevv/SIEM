"""
Process monitor — detects new process creation, suspicious processes,
privilege changes, and process injection indicators.
Every detection is tagged with a MITRE ATT&CK technique ID.
"""
import os
import re
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Set, Tuple

logger = logging.getLogger(__name__)

from collectors._paths import data_path as _data_path
_prev_pids: Set[int] = set()
_PIDS_FILE = _data_path('.prev_pids')


def _load_prev_pids() -> Set[int]:
    try:
        if os.path.exists(_PIDS_FILE):
            with open(_PIDS_FILE) as f:
                return {int(x) for x in f.read().split() if x.strip().isdigit()}
    except Exception:
        pass
    return set()


def _save_pids(pids: Set[int]):
    try:
        with open(_PIDS_FILE, 'w') as f:
            f.write('\n'.join(str(p) for p in pids))
    except Exception:
        pass


# ── MITRE ATT&CK technique lookup (pattern → technique) ──────────────────────

_MITRE_CMD_RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'nc\s+-[le]|ncat\b|netcat\b|/dev/tcp|/dev/udp',           re.I), 'T1059,T1571'),
    (re.compile(r'wget\s+http.*\|\s*(?:bash|sh|python|perl)',               re.I), 'T1105'),
    (re.compile(r'curl\s+http.*\|\s*(?:bash|sh|python|perl)',               re.I), 'T1105'),
    (re.compile(r'base64\s+-d.*\|\s*(?:bash|sh)',                          re.I), 'T1027'),
    (re.compile(r'python[23]?\s+-c.*(?:socket|subprocess|exec|eval)',       re.I), 'T1059.006'),
    (re.compile(r'perl\s+-e',                                               re.I), 'T1059.003'),
    (re.compile(r'ruby\s+-e',                                               re.I), 'T1059.004'),
    (re.compile(r'msfvenom|msfconsole|metasploit',                          re.I), 'T1587.001'),
    (re.compile(r'\bjohn\b.*wordlist|\bhashcat\b',                          re.I), 'T1110.002'),
    (re.compile(r'tcpdump\s+-i|tshark\s|wireshark',                        re.I), 'T1040'),
    (re.compile(r'\bnmap\b|\bmasscan\b',                                    re.I), 'T1046'),
    (re.compile(r'\bhydra\b|\bmedusa\b|\bcrowbar\b',                       re.I), 'T1110'),
    (re.compile(r'sqlmap|nikto|dirb|gobuster|dirsearch|feroxbuster',       re.I), 'T1190'),
    (re.compile(r'mimikatz|lazagne|secretsdump|lsassy|pypykatz',           re.I), 'T1003'),
    (re.compile(r'chmod\s+[0-7]*[67][0-7]{2}\s+/',                        re.I), 'T1548.001'),
    (re.compile(r'socat\s+.*TCP|mkfifo.*nc',                               re.I), 'T1059,T1071'),
]

_PRIV_MITRE_RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'sudo\s+-s|sudo\s+su|sudo\s+bash|sudo\s+sh',             re.I), 'T1548.003'),
    (re.compile(r'pkexec\s+(?:bash|sh)',                                   re.I), 'T1548.003'),
    (re.compile(r'^su\s*-?\s*$|su\s+-\s+root',                           re.I), 'T1548.003'),
    (re.compile(r'chmod\s+u\+s',                                           re.I), 'T1548.001'),
    (re.compile(r'python.*os\.setuid\(0\)',                                re.I), 'T1548'),
]

_PERSISTENCE_MITRE_RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'crontab\s+-[el]',                                        re.I), 'T1053.003'),
    (re.compile(r'systemctl\s+enable',                                     re.I), 'T1543.002'),
    (re.compile(r'update-rc\.d|chkconfig\s+.*\s+on',                     re.I), 'T1543.003'),
    (re.compile(r'echo.*>>\s*/etc/rc\.local',                             re.I), 'T1037.004'),
    (re.compile(r'cp\s+.*\s+/etc/init\.d/',                              re.I), 'T1543.003'),
    (re.compile(r'ln\s+.*\s+/etc/cron',                                  re.I), 'T1053.003'),
    (re.compile(r'at\s+now',                                               re.I), 'T1053.001'),
]

# Combined regex objects (legacy, kept for compatibility)
SUSPICIOUS_CMDS = re.compile(
    r'(nc\s+-[le]|ncat|netcat|/dev/tcp|/dev/udp'
    r'|wget\s+http|curl\s+http.*\|\s*(?:bash|sh|python|perl)'
    r'|base64\s+-d.*\|\s*(?:bash|sh)'
    r'|python.*-c.*(?:socket|subprocess|exec)'
    r'|perl\s+-e|ruby\s+-e'
    r'|msfvenom|msfconsole|metasploit'
    r'|john\s|hashcat'
    r'|tcpdump\s+-i|wireshark'
    r'|nmap\s|masscan\s'
    r'|hydra\s|medusa\s|crowbar\s'
    r'|sqlmap|nikto|dirb|gobuster'
    r'|mimikatz|lazagne|secretsdump'
    r'|chmod\s+[0-7]*[67][0-7]{2}\s+/)',
    re.I,
)

PRIV_ESCALATION_CMDS = re.compile(
    r'(sudo\s+-s|sudo\s+su|su\s+-\s*$|sudo\s+bash|sudo\s+sh'
    r'|pkexec\s+bash|pkexec\s+sh'
    r'|/usr/bin/python.*os\.setuid\(0\)'
    r'|chmod\s+u\+s)',
    re.I,
)

PERSISTENCE_CMDS = re.compile(
    r'(crontab\s+-e|at\s+now|systemctl\s+enable'
    r'|update-rc\.d|chkconfig\s+.*\s+on'
    r'|echo.*>>\s*/etc/rc\.local'
    r'|cp.*\s+/etc/init\.d/'
    r'|ln.*\s+/etc/cron)',
    re.I,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mitre_for_cmdline(cmdline: str, rules: List[Tuple[re.Pattern, str]]) -> str:
    for pattern, technique in rules:
        if pattern.search(cmdline):
            return technique
    return ''


def _make_process_log(
    severity: str,
    event: str,
    detail: str,
    extra: Optional[dict] = None,
    mitre: str = '',
) -> Dict[str, Any]:
    msg = f"PROCESS [{event.upper()}]: {detail}"
    fields: Dict[str, Any] = {"event_type": event, "detail": detail}
    if mitre:
        fields["mitre_technique"] = mitre
    if extra:
        fields.update(extra)
    return {
        "timestamp":     _now(),
        "level":         severity,
        "source":        "process_monitor",
        "message":       msg,
        "raw":           msg,
        "parsed_fields": fields,
    }


def _get_parent_info(ppid: Optional[int]) -> dict:
    """Safely return parent process name and cmdline."""
    if not ppid:
        return {}
    try:
        import psutil
        p = psutil.Process(ppid)
        return {
            'parent_name': p.name(),
            'parent_cmd':  ' '.join(p.cmdline() or [])[:256],
        }
    except Exception:
        return {}


# ── Windows LOLBin / malicious-use patterns ───────────────────────────────────

WIN_SUSPICIOUS_CMDS = re.compile(
    r'(powershell.*-[Ee][Nn][Cc][Oo]?[Dd]?[Ee]?[Dd]?'
    r'|powershell.*[Ii]nvoke-[Ee]xpression'
    r'|powershell.*[Dd]ownload[Ss]tring'
    r'|powershell.*-[Ww]indow[Ss]tyle\s+[Hh]id'
    r'|powershell.*-[Nn]on[Ii]nteractive'
    r'|mshta\.exe\s+https?://'
    r'|regsvr32\.exe.*\/[Ss]\s+\/[Nn]\s+\/[Uu]\s+\/[Ii]:?https?://'
    r'|rundll32\.exe.*javascript:'
    r'|certutil\.exe.*-[Uu][Rr][Ll][Cc]ache.*-[Ff]'
    r'|certutil\.exe.*-[Dd][Ee][Cc][Oo][Dd][Ee]'
    r'|bitsadmin\.exe.*\/[Tt]ransfer'
    r'|wmic\.exe.*process.*call.*create'
    r'|msiexec\.exe.*\/[Qq].*https?://'
    r'|installutil\.exe.*\/logfile.*\/logoport'
    r'|cmstp\.exe.*\/[Ss]\s'
    r'|xwizard\.exe'
    r'|wscript\.exe.*\.(vbs|js|jse|wsf)'
    r'|cscript\.exe.*\.(vbs|js|jse|wsf)'
    r'|net\s+user.*\/add'
    r'|net\s+localgroup.*administrators.*\/add'
    r'|schtasks.*\/[Cc][Rr][Ee][Aa][Tt][Ee]'
    r'|sc\s+(create|config|start)\s'
    r'|reg\.exe\s+add.*\\run'
    r'|cmd\.exe.*\/[Cc].*\.bat.*&)',
    re.I,
)

WIN_PRIV_ESCALATION = re.compile(
    r'(runas\s.*\/user:.*administrator'
    r'|whoami\s*/all'
    r'|accesschk\.exe'
    r'|powerup\.ps1'
    r'|bypassuac'
    r'|invoke-allchecks)',
    re.I,
)

WIN_CREDENTIAL_ACCESS = re.compile(
    r'(mimikatz|sekurlsa|lsadump|wce\.exe|fgdump'
    r'|procdump.*lsass'
    r'|vssadmin.*shadow.*copy'
    r'|ntdsutil.*ifm'
    r'|reg.*save.*hklm\\sam'
    r'|reg.*save.*hklm\\system'
    r'|reg.*save.*hklm\\security)',
    re.I,
)

WIN_LATERAL_MOVEMENT = re.compile(
    r'(psexec\.exe|psexesvc'
    r'|wmiexec\.py|smbexec\.py|atexec'
    r'|invoke-wmimethod.*process'
    r'|new-pssession'
    r'|enter-pssession'
    r'|net\s+use\s+\\\\)',
    re.I,
)

WIN_MITRE_RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'powershell.*-[Ee][Nn][Cc]', re.I),         'T1059.001'),
    (re.compile(r'mshta\.exe',                 re.I),         'T1218.005'),
    (re.compile(r'regsvr32.*\/[Ii].*http',     re.I),         'T1218.010'),
    (re.compile(r'rundll32.*javascript',        re.I),         'T1218.011'),
    (re.compile(r'certutil.*-[Uu][Rr][Ll]',    re.I),         'T1105'),
    (re.compile(r'bitsadmin.*\/[Tt]ransfer',    re.I),         'T1197'),
    (re.compile(r'wmic.*process.*create',       re.I),         'T1047'),
    (re.compile(r'msiexec.*https?',             re.I),         'T1218.007'),
    (re.compile(r'installutil',                 re.I),         'T1218.004'),
    (re.compile(r'schtasks.*\/create',          re.I),         'T1053.005'),
    (re.compile(r'net\s+user.*\/add',           re.I),         'T1136.001'),
    (re.compile(r'net\s+localgroup.*admin',     re.I),         'T1098'),
    (re.compile(r'mimikatz|sekurlsa',           re.I),         'T1003.001'),
    (re.compile(r'psexec|wmiexec|smbexec',      re.I),         'T1021'),
    (re.compile(r'vssadmin.*shadow',            re.I),         'T1490'),
    (re.compile(r'reg.*save.*hklm',             re.I),         'T1003.002'),
    (re.compile(r'procdump.*lsass',             re.I),         'T1003.001'),
]


def collect_processes() -> List[Dict[str, Any]]:
    """Collect new processes and check for suspicious activity (Linux + Windows)."""
    events = []

    try:
        import psutil
    except ImportError:
        return events

    global _prev_pids
    if not _prev_pids:
        _prev_pids = _load_prev_pids()
    current_pids: Set[int] = set()

    for proc in psutil.process_iter(
        ['pid', 'name', 'cmdline', 'username', 'ppid', 'status', 'create_time']
    ):
        try:
            info    = proc.info
            pid     = info['pid']
            current_pids.add(pid)
            cmdline = " ".join(info.get('cmdline') or [])

            is_new = pid not in _prev_pids and bool(_prev_pids)
            # Always run cmdline checks — even on first run (prev_pids empty)
            # so we don't miss active threats on startup.
            if is_new or not _prev_pids:
                parent  = _get_parent_info(info.get('ppid'))
                base_extra = {
                    "pid":         pid,
                    "process":     info['name'],
                    "cmdline":     cmdline[:512],
                    "user":        info.get('username', ''),
                    "ppid":        info.get('ppid'),
                    **parent,
                }

                is_windows = os.name == "nt"

                # ── Windows-specific checks ───────────────────────────────────
                if is_windows and cmdline:
                    if WIN_CREDENTIAL_ACCESS.search(cmdline):
                        mitre = _mitre_for_cmdline(cmdline, WIN_MITRE_RULES) or 'T1003'
                        events.append(_make_process_log(
                            "CRITICAL", "credential_access",
                            f"Credential access tool: [{pid}] {cmdline[:200]}",
                            {**base_extra, "event_type": "credential_access"},
                            mitre=mitre,
                        ))
                        continue

                    if WIN_LATERAL_MOVEMENT.search(cmdline):
                        mitre = _mitre_for_cmdline(cmdline, WIN_MITRE_RULES) or 'T1021'
                        events.append(_make_process_log(
                            "HIGH", "lateral_movement",
                            f"Lateral movement tool: [{pid}] {cmdline[:200]}",
                            {**base_extra, "event_type": "lateral_movement"},
                            mitre=mitre,
                        ))
                        continue

                    if WIN_SUSPICIOUS_CMDS.search(cmdline):
                        mitre = _mitre_for_cmdline(cmdline, WIN_MITRE_RULES) or 'T1059'
                        events.append(_make_process_log(
                            "CRITICAL", "suspicious_process",
                            f"Suspicious Windows process: [{pid}] {cmdline[:200]}",
                            {**base_extra, "event_type": "suspicious_process",
                             "platform": "windows"},
                            mitre=mitre,
                        ))
                        continue

                    if WIN_PRIV_ESCALATION.search(cmdline):
                        mitre = _mitre_for_cmdline(cmdline, WIN_MITRE_RULES) or 'T1548'
                        events.append(_make_process_log(
                            "HIGH", "privilege_escalation",
                            f"Windows priv-esc: [{pid}] {cmdline[:200]}",
                            {**base_extra, "event_type": "privilege_escalation",
                             "platform": "windows"},
                            mitre=mitre,
                        ))
                        continue

                # ── Cross-platform checks ─────────────────────────────────────
                if cmdline and SUSPICIOUS_CMDS.search(cmdline):
                    mitre = _mitre_for_cmdline(cmdline, _MITRE_CMD_RULES) or 'T1059'
                    events.append(_make_process_log(
                        "CRITICAL", "suspicious_process",
                        f"Suspicious process: [{pid}] {cmdline[:200]}",
                        {**base_extra, "event_type": "suspicious_process"},
                        mitre=mitre,
                    ))

                elif cmdline and PRIV_ESCALATION_CMDS.search(cmdline):
                    mitre = _mitre_for_cmdline(cmdline, _PRIV_MITRE_RULES) or 'T1548'
                    events.append(_make_process_log(
                        "HIGH", "privilege_escalation",
                        f"Privilege escalation: [{pid}] {cmdline[:200]}",
                        {**base_extra, "event_type": "privilege_escalation"},
                        mitre=mitre,
                    ))

                elif cmdline and PERSISTENCE_CMDS.search(cmdline):
                    mitre = _mitre_for_cmdline(cmdline, _PERSISTENCE_MITRE_RULES) or 'T1053'
                    events.append(_make_process_log(
                        "MEDIUM", "persistence_attempt",
                        f"Persistence mechanism: [{pid}] {cmdline[:200]}",
                        {**base_extra, "event_type": "persistence_attempt"},
                        mitre=mitre,
                    ))

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        except Exception as e:
            logger.debug(f"Process iter error: {e}")

    _prev_pids = current_pids
    _save_pids(current_pids)
    return events
