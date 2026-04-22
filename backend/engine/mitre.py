"""
MITRE ATT&CK mapping — automatically tags alerts with tactics and techniques
based on decoded event types and rule categories.
"""
from typing import Tuple, Optional, Dict, Any

# event_type → (tactic, technique_id, technique_name)
_EVENT_MAP: Dict[str, Tuple[str, str, str]] = {
    # Initial Access
    "ssh_failed":            ("Initial Access",         "T1190",     "Exploit Public-Facing Application"),
    "authentication_failed": ("Credential Access",      "T1110",     "Brute Force"),
    "brute_force_ssh":       ("Credential Access",      "T1110.001", "Password Guessing"),
    "invalid_user":          ("Reconnaissance",         "T1592",     "Gather Victim Identity Information"),
    "ssh_invalid_user":      ("Reconnaissance",         "T1592",     "Gather Victim Identity Information"),

    # Execution
    "sudo_command":          ("Privilege Escalation",   "T1548.003", "Sudo and Sudo Caching"),
    "sudo_auth_failed":      ("Privilege Escalation",   "T1548.003", "Sudo and Sudo Caching"),
    "cron_job":              ("Execution",              "T1053.003", "Scheduled Task/Job: Cron"),
    "process_execution":     ("Execution",              "T1059",     "Command and Scripting Interpreter"),
    "user_command":          ("Execution",              "T1059",     "Command and Scripting Interpreter"),

    # Persistence
    "user_created":          ("Persistence",            "T1136.001", "Create Account: Local Account"),
    "group_created":         ("Persistence",            "T1136",     "Create Account"),
    "system_call":           ("Execution",              "T1106",     "Native API"),

    # Privilege Escalation
    "ssh_accepted":          ("Lateral Movement",       "T1021.004", "Remote Services: SSH"),
    "pam_session_opened":    ("Lateral Movement",       "T1021.004", "Remote Services: SSH"),
    "authentication_success":("Initial Access",         "T1078",     "Valid Accounts"),

    # Defense Evasion
    "fim_modified":          ("Defense Evasion",        "T1070",     "Indicator Removal"),
    "fim_deleted":           ("Defense Evasion",        "T1070.004", "File Deletion"),
    "pam_session_closed":    ("Defense Evasion",        "T1070",     "Indicator Removal"),

    # Credential Access
    "pam_auth_failed":       ("Credential Access",      "T1110",     "Brute Force"),
    "pam_account_locked":    ("Credential Access",      "T1110",     "Brute Force"),
    "max_auth_exceeded":     ("Credential Access",      "T1110.001", "Password Guessing"),

    # Discovery
    "network_connection":    ("Discovery",              "T1046",     "Network Service Discovery"),
    "http_request":          ("Discovery",              "T1595",     "Active Scanning"),

    # Impact
    "oom_kill":              ("Impact",                 "T1499",     "Endpoint Denial of Service"),
    "service_failed":        ("Impact",                 "T1489",     "Service Stop"),
    "service_killed":        ("Impact",                 "T1489",     "Service Stop"),

    # Exfiltration / C2
    "firewall_block":        ("Command and Control",    "T1071",     "Application Layer Protocol"),
    "ufw_block":             ("Command and Control",    "T1071",     "Application Layer Protocol"),

    # FIM alerts
    "fim_created":           ("Defense Evasion",        "T1036",     "Masquerading"),
    "fim_permissions_changed": ("Privilege Escalation", "T1222",     "File and Directory Permissions Modification"),
    "fim_ownership_changed": ("Privilege Escalation",   "T1222",     "File and Directory Permissions Modification"),

    # Container
    "container_kill":        ("Impact",                 "T1489",     "Service Stop"),
    "container_stopped":     ("Impact",                 "T1489",     "Service Stop"),

    # Rootkit indicators
    "rootkit_detected":      ("Defense Evasion",        "T1014",     "Rootkit"),
    "hidden_process":        ("Defense Evasion",        "T1014",     "Rootkit"),
    "hidden_file":           ("Defense Evasion",        "T1564.001", "Hidden Files and Directories"),
    "kernel_module_loaded":  ("Persistence",            "T1547.006", "Boot or Logon Autostart: Kernel Modules"),
}

# category → (tactic, technique_id)
_CATEGORY_MAP: Dict[str, Tuple[str, str]] = {
    "authentication":        ("Credential Access",      "T1110"),
    "privilege_escalation":  ("Privilege Escalation",   "T1548"),
    "network":               ("Command and Control",    "T1071"),
    "attack":                ("Credential Access",      "T1110"),
    "availability":          ("Impact",                 "T1499"),
    "fim":                   ("Defense Evasion",        "T1070"),
    "rootcheck":             ("Defense Evasion",        "T1014"),
    "docker":                ("Execution",              "T1610"),
    "audit":                 ("Collection",             "T1005"),
    "process":               ("Execution",              "T1059"),
}


def get_mitre_tags(
    event_type: Optional[str] = None,
    category: Optional[str] = None,
    rule_mitre_tactic: Optional[str] = None,
    rule_mitre_technique: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Return (tactic, technique_id) for a given event.
    Priority: explicit rule mapping > event_type > category.
    """
    if rule_mitre_tactic:
        return rule_mitre_tactic, rule_mitre_technique

    if event_type and event_type in _EVENT_MAP:
        tactic, technique, _ = _EVENT_MAP[event_type]
        return tactic, technique

    if category and category in _CATEGORY_MAP:
        tactic, technique = _CATEGORY_MAP[category]
        return tactic, technique

    return None, None


def get_technique_name(technique_id: str) -> Optional[str]:
    for tactic, tech_id, tech_name in _EVENT_MAP.values():
        if tech_id == technique_id:
            return tech_name
    return None


def level_to_severity(level: int) -> str:
    """Convert Wazuh-style level (0-15) to severity string."""
    if level >= 13:
        return "CRITICAL"
    if level >= 9:
        return "HIGH"
    if level >= 5:
        return "MEDIUM"
    return "LOW"


def severity_to_level(severity: str) -> int:
    return {"CRITICAL": 13, "HIGH": 9, "MEDIUM": 5, "LOW": 2}.get(severity, 5)
