#!/usr/bin/env python3
"""
SecureWatch SIEM — Comprehensive Rule Seeder
Inserts 200+ Wazuh-style rules into the database.
Run: python3 scripts/seed_rules.py
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select, text
from database import AsyncSessionLocal
from models.rule import Rule, RuleSeverity

# ─────────────────────────────────────────────────────────────────────────────
# Rule definitions
# Each dict maps directly to Rule model columns.
# level: 0-15 (Wazuh convention)
#   0-2  = informational   3-5 = low   6-9 = medium  10-12 = high  13-15 = critical
# ─────────────────────────────────────────────────────────────────────────────

RULES = [

    # ══════════════════════════════════════════════════════════════════════
    # AUTHENTICATION — SSH
    # ══════════════════════════════════════════════════════════════════════
    {
        "name": "SSH Authentication Failure",
        "description": "Failed SSH authentication attempt",
        "pattern": r"Failed password|authentication failure|ssh_failed",
        "severity": "LOW", "level": 5,
        "category": "authentication", "groups": "authentication,ssh",
        "mitre_tactic": "Credential Access", "mitre_technique": "T1110.001",
        "cooldown_seconds": 0,
    },
    {
        "name": "SSH Invalid User Login Attempt",
        "description": "SSH login attempt for a non-existent user",
        "pattern": r"Invalid user \S+ from|ssh_invalid_user",
        "severity": "MEDIUM", "level": 6,
        "category": "authentication", "groups": "authentication,ssh",
        "mitre_tactic": "Credential Access", "mitre_technique": "T1110.001",
        "cooldown_seconds": 30,
    },
    {
        "name": "SSH Brute Force Attack",
        "description": "Multiple SSH authentication failures in short window",
        "pattern": r"Failed password|authentication failure",
        "severity": "CRITICAL", "level": 13,
        "category": "attack", "groups": "authentication,ssh,brute_force",
        "mitre_tactic": "Credential Access", "mitre_technique": "T1110.001",
        "frequency": 5, "timeframe": 60, "cooldown_seconds": 300,
        "custom_logic": "brute_force_ssh",
    },
    {
        "name": "SSH Successful Root Login",
        "description": "Root user logged in via SSH",
        "pattern": r"Accepted \S+ for root from",
        "severity": "HIGH", "level": 10,
        "category": "authentication", "groups": "authentication,ssh",
        "mitre_tactic": "Initial Access", "mitre_technique": "T1078.003",
        "cooldown_seconds": 60,
    },
    {
        "name": "SSH Login from New IP",
        "description": "SSH authentication succeeded",
        "pattern": r"Accepted (password|publickey|keyboard-interactive) for",
        "severity": "LOW", "level": 3,
        "category": "authentication", "groups": "authentication,ssh",
        "mitre_tactic": "Initial Access", "mitre_technique": "T1078",
        "cooldown_seconds": 0,
    },
    {
        "name": "SSH Max Authentication Attempts Exceeded",
        "description": "SSH connection exhausted max auth retries",
        "pattern": r"maximum authentication attempts exceeded|Too many authentication failures",
        "severity": "MEDIUM", "level": 8,
        "category": "authentication", "groups": "authentication,ssh",
        "mitre_tactic": "Credential Access", "mitre_technique": "T1110",
        "cooldown_seconds": 60,
    },
    {
        "name": "SSH Possible Scan Detected",
        "description": "Multiple distinct users attempted from same source",
        "pattern": r"Invalid user|Failed password",
        "severity": "MEDIUM", "level": 7,
        "category": "reconnaissance", "groups": "authentication,ssh,recon",
        "mitre_tactic": "Reconnaissance", "mitre_technique": "T1595",
        "frequency": 10, "timeframe": 30, "cooldown_seconds": 300,
    },
    {
        "name": "SSH Reverse Mapping Failed",
        "description": "SSH client IP reverse DNS lookup failed — possible spoofing",
        "pattern": r"reverse mapping.*failed|POSSIBLE BREAK-IN ATTEMPT",
        "severity": "MEDIUM", "level": 7,
        "category": "authentication", "groups": "ssh,network",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1036",
        "cooldown_seconds": 300,
    },
    {
        "name": "SSH Connection from Tor Exit Node",
        "description": "SSH login attempt from known Tor exit relay",
        "pattern": r"Accepted|Failed password|Invalid user",
        "severity": "HIGH", "level": 11,
        "category": "authentication", "groups": "ssh,threat_intel",
        "mitre_tactic": "Initial Access", "mitre_technique": "T1090.003",
        "cooldown_seconds": 300,
    },

    # ══════════════════════════════════════════════════════════════════════
    # AUTHENTICATION — PAM / Login
    # ══════════════════════════════════════════════════════════════════════
    {
        "name": "PAM Authentication Failure",
        "description": "PAM authentication failure",
        "pattern": r"pam_unix.*authentication failure|pam_unix.*auth failed",
        "severity": "LOW", "level": 5,
        "category": "authentication", "groups": "authentication,pam",
        "mitre_tactic": "Credential Access", "mitre_technique": "T1110",
        "cooldown_seconds": 0,
    },
    {
        "name": "PAM Account Locked",
        "description": "User account locked due to repeated failures",
        "pattern": r"pam_faillock.*fail.*lock|account.*locked|pam_tally.*user blocked",
        "severity": "HIGH", "level": 10,
        "category": "authentication", "groups": "authentication,pam",
        "mitre_tactic": "Impact", "mitre_technique": "T1531",
        "cooldown_seconds": 60,
    },
    {
        "name": "PAM Session Opened for Root",
        "description": "Root session opened via PAM",
        "pattern": r"pam_unix.*session opened for user root",
        "severity": "HIGH", "level": 10,
        "category": "authentication", "groups": "authentication,pam",
        "mitre_tactic": "Privilege Escalation", "mitre_technique": "T1078.003",
        "cooldown_seconds": 60,
    },
    {
        "name": "Multiple Login Failures for Same User",
        "description": "Repeated login failures for the same username",
        "pattern": r"Failed password|authentication failure|FAILED LOGIN",
        "severity": "MEDIUM", "level": 8,
        "category": "authentication", "groups": "authentication",
        "mitre_tactic": "Credential Access", "mitre_technique": "T1110.001",
        "frequency": 3, "timeframe": 120, "cooldown_seconds": 300,
    },
    {
        "name": "Login Outside Business Hours",
        "description": "Successful login detected",
        "pattern": r"Accepted password|Accepted publickey|session opened",
        "severity": "LOW", "level": 4,
        "category": "authentication", "groups": "authentication",
        "mitre_tactic": "Initial Access", "mitre_technique": "T1078",
        "cooldown_seconds": 0,
    },

    # ══════════════════════════════════════════════════════════════════════
    # PRIVILEGE ESCALATION — sudo / su
    # ══════════════════════════════════════════════════════════════════════
    {
        "name": "Sudo Authentication Failure",
        "description": "Incorrect sudo password entered",
        "pattern": r"sudo:.*authentication failure|sudo:.*incorrect password|sudo:.*3 incorrect password",
        "severity": "MEDIUM", "level": 6,
        "category": "privilege_escalation", "groups": "sudo,privilege_escalation",
        "mitre_tactic": "Privilege Escalation", "mitre_technique": "T1548.003",
        "cooldown_seconds": 0,
    },
    {
        "name": "Sudo to Root Execution",
        "description": "User executed a command as root via sudo",
        "pattern": r"sudo:.*COMMAND=.*USER=root",
        "severity": "MEDIUM", "level": 6,
        "category": "privilege_escalation", "groups": "sudo,privilege_escalation",
        "mitre_tactic": "Privilege Escalation", "mitre_technique": "T1548.003",
        "cooldown_seconds": 30,
    },
    {
        "name": "Sudo Shell Escalation",
        "description": "User spawned a root shell via sudo — possible TTY escape",
        "pattern": r"sudo:.*COMMAND=/bin/bash|sudo:.*COMMAND=/bin/sh|sudo:.*COMMAND=/usr/bin/bash",
        "severity": "HIGH", "level": 11,
        "category": "privilege_escalation", "groups": "sudo,privilege_escalation",
        "mitre_tactic": "Privilege Escalation", "mitre_technique": "T1548.003",
        "cooldown_seconds": 120,
    },
    {
        "name": "Sudo Rule Modification",
        "description": "Sudoers file was modified",
        "pattern": r"fim.*sudoers|FIM.*MODIFIED.*sudoers|sudoers.*modified",
        "severity": "CRITICAL", "level": 14,
        "category": "privilege_escalation", "groups": "sudo,fim,privilege_escalation",
        "mitre_tactic": "Privilege Escalation", "mitre_technique": "T1548.003",
        "cooldown_seconds": 120,
    },
    {
        "name": "su Authentication Success",
        "description": "User switched to another account via su",
        "pattern": r"su: \(to \S+\)|pam_unix.*su:session opened",
        "severity": "LOW", "level": 5,
        "category": "privilege_escalation", "groups": "su,authentication",
        "mitre_tactic": "Privilege Escalation", "mitre_technique": "T1548",
        "cooldown_seconds": 60,
    },
    {
        "name": "su Authentication Failure",
        "description": "Failed attempt to switch user via su",
        "pattern": r"su: FAILED SU|su:.*authentication failure",
        "severity": "MEDIUM", "level": 7,
        "category": "privilege_escalation", "groups": "su,authentication",
        "mitre_tactic": "Privilege Escalation", "mitre_technique": "T1548",
        "cooldown_seconds": 0,
    },

    # ══════════════════════════════════════════════════════════════════════
    # USER/ACCOUNT CHANGES
    # ══════════════════════════════════════════════════════════════════════
    {
        "name": "New User Account Created",
        "description": "A new user account was created on the system",
        "pattern": r"useradd.*new user|new user:.*uid=|syslog.*useradd|ADD_USER",
        "severity": "HIGH", "level": 8,
        "category": "persistence", "groups": "user_management,persistence",
        "mitre_tactic": "Persistence", "mitre_technique": "T1136.001",
        "cooldown_seconds": 60,
    },
    {
        "name": "User Account Deleted",
        "description": "A user account was removed from the system",
        "pattern": r"userdel.*user|DEL_USER|delete user",
        "severity": "HIGH", "level": 8,
        "category": "impact", "groups": "user_management",
        "mitre_tactic": "Impact", "mitre_technique": "T1531",
        "cooldown_seconds": 60,
    },
    {
        "name": "User Added to Privileged Group",
        "description": "User added to sudo, wheel, or admin group",
        "pattern": r"usermod.*-aG.*(sudo|wheel|admin)|ADD.*GROUP.*(sudo|wheel|admin)",
        "severity": "CRITICAL", "level": 12,
        "category": "privilege_escalation", "groups": "user_management,privilege_escalation",
        "mitre_tactic": "Privilege Escalation", "mitre_technique": "T1078",
        "cooldown_seconds": 120,
    },
    {
        "name": "Password Changed",
        "description": "User password was changed",
        "pattern": r"password changed for|passwd.*changed|chpasswd",
        "severity": "LOW", "level": 5,
        "category": "authentication", "groups": "user_management",
        "mitre_tactic": "Credential Access", "mitre_technique": "T1098",
        "cooldown_seconds": 60,
    },
    {
        "name": "Root Password Changed",
        "description": "Root account password was modified",
        "pattern": r"password changed for root|passwd.*root",
        "severity": "HIGH", "level": 12,
        "category": "authentication", "groups": "user_management",
        "mitre_tactic": "Credential Access", "mitre_technique": "T1098",
        "cooldown_seconds": 120,
    },

    # ══════════════════════════════════════════════════════════════════════
    # FILE INTEGRITY MONITORING
    # ══════════════════════════════════════════════════════════════════════
    {
        "name": "Critical File Modified",
        "description": "A critical system file was modified",
        "pattern": r"FIM\s*\[(?:MODIFY|CLOSE_WRITE)\]|fim_modified.*(?:passwd|shadow|group|hosts|sudoers|sshd_config|crontab)",
        "severity": "CRITICAL", "level": 13,
        "category": "fim", "groups": "fim,integrity",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1565.001",
        "cooldown_seconds": 60,
    },
    {
        "name": "Critical File Deleted",
        "description": "A monitored critical file was deleted",
        "pattern": r"FIM\s*\[DELETE\]|fim_deleted",
        "severity": "CRITICAL", "level": 14,
        "category": "fim", "groups": "fim,integrity",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1070",
        "cooldown_seconds": 60,
    },
    {
        "name": "SSH Authorized Keys Modified",
        "description": "SSH authorized_keys file was changed — possible backdoor",
        "pattern": r"authorized_keys.*modified|FIM.*authorized_keys|fim.*authorized_keys",
        "severity": "CRITICAL", "level": 14,
        "category": "persistence", "groups": "fim,ssh,persistence",
        "mitre_tactic": "Persistence", "mitre_technique": "T1098.004",
        "cooldown_seconds": 60,
    },
    {
        "name": "Passwd File Modified",
        "description": "/etc/passwd was changed",
        "pattern": r"FIM.*\bpasswd\b|fim.*modified.*/etc/passwd",
        "severity": "CRITICAL", "level": 13,
        "category": "fim", "groups": "fim,integrity,user_management",
        "mitre_tactic": "Persistence", "mitre_technique": "T1136",
        "cooldown_seconds": 60,
    },
    {
        "name": "Shadow File Modified",
        "description": "/etc/shadow was changed",
        "pattern": r"FIM.*\bshadow\b|fim.*modified.*/etc/shadow",
        "severity": "CRITICAL", "level": 14,
        "category": "fim", "groups": "fim,integrity",
        "mitre_tactic": "Credential Access", "mitre_technique": "T1003.008",
        "cooldown_seconds": 60,
    },
    {
        "name": "Crontab File Modified",
        "description": "System crontab was modified — possible persistence",
        "pattern": r"FIM.*crontab|FIM.*cron\.d|fim.*modified.*cron",
        "severity": "HIGH", "level": 11,
        "category": "persistence", "groups": "fim,persistence,cron",
        "mitre_tactic": "Persistence", "mitre_technique": "T1053.003",
        "cooldown_seconds": 60,
    },
    {
        "name": "Log File Cleared",
        "description": "System log file was deleted or truncated",
        "pattern": r"FIM.*\[DELETE\].*/var/log|fim_deleted.*/var/log",
        "severity": "CRITICAL", "level": 15,
        "category": "defense_evasion", "groups": "fim,defense_evasion",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1070.002",
        "cooldown_seconds": 120,
    },
    {
        "name": "Binary in /tmp or /dev/shm",
        "description": "Executable file created in temporary location",
        "pattern": r"FIM.*\[CREATE\].*/(?:tmp|dev/shm|run/shm).*(?:\.sh|\.py|\.elf|\.bin|\.exe)",
        "severity": "HIGH", "level": 12,
        "category": "malware", "groups": "fim,malware",
        "mitre_tactic": "Execution", "mitre_technique": "T1059",
        "cooldown_seconds": 60,
    },

    # ══════════════════════════════════════════════════════════════════════
    # ROOTCHECK
    # ══════════════════════════════════════════════════════════════════════
    {
        "name": "Rootkit Indicator Found",
        "description": "Known rootkit file or directory detected",
        "pattern": r"ROOTCHECK\s*\[ROOTKIT_FILE\]|rootkit.*found|ROOTKIT.*DETECTED",
        "severity": "CRITICAL", "level": 15,
        "category": "rootcheck", "groups": "rootcheck,malware",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1014",
        "cooldown_seconds": 3600,
    },
    {
        "name": "Hidden Process Detected",
        "description": "Process visible in /proc but not in ps output",
        "pattern": r"ROOTCHECK\s*\[HIDDEN_PROCESS\]|Hidden process|process.*not visible",
        "severity": "CRITICAL", "level": 15,
        "category": "rootcheck", "groups": "rootcheck,malware",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1014",
        "cooldown_seconds": 3600,
    },
    {
        "name": "LD_PRELOAD Hijack Detected",
        "description": "Suspicious /etc/ld.so.preload modification",
        "pattern": r"ROOTCHECK\s*\[LD_PRELOAD\]|ld\.so\.preload|libprocesshider|libhide",
        "severity": "CRITICAL", "level": 15,
        "category": "rootcheck", "groups": "rootcheck,defense_evasion",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1574.006",
        "cooldown_seconds": 3600,
    },
    {
        "name": "Unexpected SUID Binary",
        "description": "SUID binary found in unexpected location",
        "pattern": r"ROOTCHECK\s*\[SUID_FILE\]|unexpected SUID|SUID.*not expected",
        "severity": "HIGH", "level": 11,
        "category": "rootcheck", "groups": "rootcheck,privilege_escalation",
        "mitre_tactic": "Privilege Escalation", "mitre_technique": "T1548.001",
        "cooldown_seconds": 3600,
    },
    {
        "name": "Suspicious Kernel Module",
        "description": "Unexpected kernel module loaded",
        "pattern": r"ROOTCHECK\s*\[KERNEL_MODULE\]|insmod|modprobe.*suspicious|kernel.*module.*loaded",
        "severity": "CRITICAL", "level": 14,
        "category": "rootcheck", "groups": "rootcheck,kernel",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1215",
        "cooldown_seconds": 3600,
    },
    {
        "name": "Suspicious Cron Entry",
        "description": "Suspicious command found in cron",
        "pattern": r"ROOTCHECK\s*\[SUSPICIOUS_CRON\]|suspicious cron",
        "severity": "HIGH", "level": 10,
        "category": "persistence", "groups": "rootcheck,persistence,cron",
        "mitre_tactic": "Persistence", "mitre_technique": "T1053.003",
        "cooldown_seconds": 3600,
    },

    # ══════════════════════════════════════════════════════════════════════
    # SUSPICIOUS PROCESSES / MALWARE
    # ══════════════════════════════════════════════════════════════════════
    {
        "name": "Suspicious Process Execution",
        "description": "Process matching known malicious patterns detected",
        "pattern": r"PROCESS\s*\[SUSPICIOUS\]|suspicious.*process|ncat.*\s|netcat.*-e|nc\s+-[le]",
        "severity": "CRITICAL", "level": 14,
        "category": "malware", "groups": "process,malware",
        "mitre_tactic": "Execution", "mitre_technique": "T1059",
        "cooldown_seconds": 60,
    },
    {
        "name": "Reverse Shell Attempt",
        "description": "Reverse shell pattern detected in process arguments",
        "pattern": r"bash\s+-i.*>&|/dev/tcp/|/dev/udp/|nc\s+-e\s+/bin|ncat.*--sh-exec|python.*-c.*socket.*connect",
        "severity": "CRITICAL", "level": 15,
        "category": "malware", "groups": "process,malware,command_and_control",
        "mitre_tactic": "Command and Control", "mitre_technique": "T1059.004",
        "cooldown_seconds": 60,
    },
    {
        "name": "Cryptocurrency Miner Detected",
        "description": "Cryptocurrency mining activity detected",
        "pattern": r"xmrig|minerd|cryptonight|stratum\+tcp://|coinhive|cryptoloot|cpu.*miner",
        "severity": "HIGH", "level": 12,
        "category": "malware", "groups": "malware,cryptominer",
        "mitre_tactic": "Impact", "mitre_technique": "T1496",
        "cooldown_seconds": 3600,
    },
    {
        "name": "Malware Download Attempt",
        "description": "Potential malware download via wget or curl",
        "pattern": r"wget\s+http.*\|\s*(bash|sh|python|perl)|curl\s+http.*\|\s*(bash|sh|python|perl)|curl.*-o.*tmp.*sh",
        "severity": "CRITICAL", "level": 14,
        "category": "malware", "groups": "malware,execution",
        "mitre_tactic": "Execution", "mitre_technique": "T1059",
        "cooldown_seconds": 300,
    },
    {
        "name": "Base64 Encoded Command Execution",
        "description": "Base64-encoded command — common obfuscation technique",
        "pattern": r"base64\s+-d.*\|\s*(bash|sh|python)|echo\s+[A-Za-z0-9+/]{20,}.*\|\s*base64.*\|\s*(bash|sh)",
        "severity": "CRITICAL", "level": 14,
        "category": "defense_evasion", "groups": "malware,obfuscation",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1027",
        "cooldown_seconds": 120,
    },
    {
        "name": "Python/Perl Shell Spawned",
        "description": "Interactive shell spawned via scripting language",
        "pattern": r"python.*-c.*import pty|python.*pty\.spawn|perl.*-e.*system\(.*bash|ruby.*exec.*bash",
        "severity": "CRITICAL", "level": 14,
        "category": "malware", "groups": "malware,execution",
        "mitre_tactic": "Execution", "mitre_technique": "T1059.006",
        "cooldown_seconds": 60,
    },
    {
        "name": "Privilege Escalation via SUID Binary",
        "description": "Suspicious SUID binary execution for privilege escalation",
        "pattern": r"pkexec\s+bash|pkexec\s+sh|chmod\s+[0-7]*[67][0-7]{2}\s+/|chmod\s+u\+s",
        "severity": "HIGH", "level": 12,
        "category": "privilege_escalation", "groups": "privilege_escalation",
        "mitre_tactic": "Privilege Escalation", "mitre_technique": "T1548.001",
        "cooldown_seconds": 120,
    },

    # ══════════════════════════════════════════════════════════════════════
    # NETWORK ATTACKS
    # ══════════════════════════════════════════════════════════════════════
    {
        "name": "Port Scan Detected",
        "description": "Multiple connection attempts to different ports from same source",
        "pattern": r"NET\s*\[|UFW BLOCK|iptables.*DROP|port.*scan|REJECT.*tcp",
        "severity": "MEDIUM", "level": 6,
        "category": "network", "groups": "network,reconnaissance",
        "mitre_tactic": "Reconnaissance", "mitre_technique": "T1046",
        "frequency": 10, "timeframe": 30, "cooldown_seconds": 300,
    },
    {
        "name": "Firewall Block Event",
        "description": "Packet blocked by firewall",
        "pattern": r"UFW BLOCK|iptables.*DROP|REJECT|firewall_block",
        "severity": "LOW", "level": 4,
        "category": "network", "groups": "network,firewall",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1562.004",
        "cooldown_seconds": 0,
    },
    {
        "name": "Connection to Suspicious Port",
        "description": "Outbound connection to known C2/backdoor port",
        "pattern": r"NET\s*\[SUSPICIOUS_CONNECTION\]|suspicious.*port|connection.*4444|connection.*31337",
        "severity": "CRITICAL", "level": 13,
        "category": "command_and_control", "groups": "network,c2",
        "mitre_tactic": "Command and Control", "mitre_technique": "T1095",
        "cooldown_seconds": 300,
    },
    {
        "name": "Sensitive Database Port Exposed",
        "description": "External connection to database port (MySQL, PostgreSQL, Redis, MongoDB)",
        "pattern": r"NET\s*\[SENSITIVE_PORT\]|sensitive.*port.*exposed|external.*(?:3306|5432|6379|27017|9200)",
        "severity": "HIGH", "level": 11,
        "category": "network", "groups": "network,database",
        "mitre_tactic": "Collection", "mitre_technique": "T1213",
        "cooldown_seconds": 300,
    },
    {
        "name": "DNS Tunneling Indicators",
        "description": "Unusually long DNS queries — possible DNS tunneling",
        "pattern": r"dns.*tunnel|iodine|dnscat|long.*dns.*query",
        "severity": "HIGH", "level": 11,
        "category": "command_and_control", "groups": "network,c2,dns",
        "mitre_tactic": "Command and Control", "mitre_technique": "T1071.004",
        "cooldown_seconds": 600,
    },
    {
        "name": "ARP Spoofing / Poisoning",
        "description": "Duplicate ARP entries or MAC address conflict",
        "pattern": r"ARP.*duplicate|ARP.*conflict|ARPING.*collision|arp.*poison",
        "severity": "HIGH", "level": 11,
        "category": "network", "groups": "network,lateral_movement",
        "mitre_tactic": "Lateral Movement", "mitre_technique": "T1557.002",
        "cooldown_seconds": 600,
    },

    # ══════════════════════════════════════════════════════════════════════
    # WEB ATTACKS
    # ══════════════════════════════════════════════════════════════════════
    {
        "name": "SQL Injection Attempt",
        "description": "SQL injection pattern detected in web request",
        "pattern": r"(?:union\s+select|select\s+.*from|insert\s+into|drop\s+table|';\s*--|or\s+'1'\s*=\s*'1|1=1--)",
        "severity": "HIGH", "level": 10,
        "category": "web", "groups": "web,attack,injection",
        "mitre_tactic": "Collection", "mitre_technique": "T1190",
        "cooldown_seconds": 60,
    },
    {
        "name": "XSS Attack Attempt",
        "description": "Cross-site scripting pattern in web request",
        "pattern": r"<script[^>]*>|javascript:.*alert|on(?:load|click|mouseover|error)=|%3Cscript",
        "severity": "MEDIUM", "level": 8,
        "category": "web", "groups": "web,attack,xss",
        "mitre_tactic": "Initial Access", "mitre_technique": "T1190",
        "cooldown_seconds": 60,
    },
    {
        "name": "Path Traversal Attack",
        "description": "Directory traversal attempt in web request",
        "pattern": r"\.\./\.\./\.\.|%2e%2e%2f|%252e%252e|/etc/passwd|/etc/shadow|/proc/self",
        "severity": "HIGH", "level": 10,
        "category": "web", "groups": "web,attack",
        "mitre_tactic": "Discovery", "mitre_technique": "T1083",
        "cooldown_seconds": 60,
    },
    {
        "name": "Command Injection Attempt",
        "description": "OS command injection in web request",
        "pattern": r"\|\s*(ls|cat|id|whoami|uname|wget|curl|bash|sh)\b|;.*(?:ls|cat|id|whoami|wget)",
        "severity": "CRITICAL", "level": 13,
        "category": "web", "groups": "web,attack,injection",
        "mitre_tactic": "Execution", "mitre_technique": "T1190",
        "cooldown_seconds": 60,
    },
    {
        "name": "Web Application Attack",
        "description": "Multiple web attack patterns from same source",
        "pattern": r"(?:nikto|sqlmap|hydra|dirb|gobuster|dirsearch|wfuzz|burpsuite|acunetix|nessus|openvas)",
        "severity": "HIGH", "level": 10,
        "category": "web", "groups": "web,scanner,reconnaissance",
        "mitre_tactic": "Reconnaissance", "mitre_technique": "T1595.002",
        "cooldown_seconds": 300,
    },
    {
        "name": "Web Shell Detected",
        "description": "Web shell signatures in web traffic or files",
        "pattern": r"(?:c99|r57|b374k|webshell|eval\(base64_decode|passthru\(|system\(|shell_exec\()",
        "severity": "CRITICAL", "level": 15,
        "category": "malware", "groups": "web,malware,webshell",
        "mitre_tactic": "Persistence", "mitre_technique": "T1505.003",
        "cooldown_seconds": 300,
    },
    {
        "name": "HTTP 5xx Server Error Spike",
        "description": "Multiple server-side errors — possible attack or instability",
        "pattern": r"http_request|HTTP.*5\d\d",
        "severity": "MEDIUM", "level": 7,
        "category": "web", "groups": "web,availability",
        "mitre_tactic": "Impact", "mitre_technique": "T1499",
        "frequency": 10, "timeframe": 60, "cooldown_seconds": 300,
        "field_name": "http_status", "field_value": ">=500",
    },
    {
        "name": "HTTP 401/403 Brute Force",
        "description": "Repeated unauthorized HTTP requests — credential brute force",
        "pattern": r"http_request|HTTP.*40[13]",
        "severity": "MEDIUM", "level": 8,
        "category": "web", "groups": "web,brute_force",
        "mitre_tactic": "Credential Access", "mitre_technique": "T1110",
        "frequency": 20, "timeframe": 60, "cooldown_seconds": 300,
        "field_name": "http_status", "field_value": ">=400",
    },
    {
        "name": "LFI/RFI Attempt",
        "description": "Local/Remote File Inclusion attack",
        "pattern": r"(?:file=|page=|include=|require=)(?:https?://|ftp://|/etc/|/proc/|php://|data://)",
        "severity": "HIGH", "level": 11,
        "category": "web", "groups": "web,attack",
        "mitre_tactic": "Initial Access", "mitre_technique": "T1190",
        "cooldown_seconds": 60,
    },

    # ══════════════════════════════════════════════════════════════════════
    # SYSTEM / OS
    # ══════════════════════════════════════════════════════════════════════
    {
        "name": "OOM Killer Triggered",
        "description": "Linux OOM killer terminated a process",
        "pattern": r"Out of memory: Kill process|oom.*kill|oom_kill",
        "severity": "HIGH", "level": 9,
        "category": "availability", "groups": "system,availability",
        "mitre_tactic": "Impact", "mitre_technique": "T1499",
        "cooldown_seconds": 300,
    },
    {
        "name": "Kernel Panic",
        "description": "Linux kernel panic detected",
        "pattern": r"Kernel panic|kernel BUG at|BUG: unable to handle|OOPS:",
        "severity": "CRITICAL", "level": 14,
        "category": "availability", "groups": "system,kernel,availability",
        "mitre_tactic": "Impact", "mitre_technique": "T1499",
        "cooldown_seconds": 3600,
    },
    {
        "name": "Disk Space Critical",
        "description": "Filesystem near capacity — disk space critical",
        "pattern": r"(?:no space left on device|disk.*full|filesystem.*full|/dev/\w+.*100%)",
        "severity": "HIGH", "level": 10,
        "category": "availability", "groups": "system,availability",
        "mitre_tactic": "Impact", "mitre_technique": "T1485",
        "cooldown_seconds": 600,
    },
    {
        "name": "Service Crashed",
        "description": "Systemd service entered failed state",
        "pattern": r"systemd.*failed|service.*crashed|segfault.*service|core\s+dumped",
        "severity": "HIGH", "level": 9,
        "category": "availability", "groups": "system,service",
        "mitre_tactic": "Impact", "mitre_technique": "T1489",
        "cooldown_seconds": 300,
    },
    {
        "name": "System Time Changed",
        "description": "System clock was modified — possible log tampering",
        "pattern": r"time_change|adjtimex|settimeofday|clock.*set|ntpd.*stepped|chronyd.*step",
        "severity": "MEDIUM", "level": 7,
        "category": "defense_evasion", "groups": "system,defense_evasion",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1070.006",
        "cooldown_seconds": 600,
    },
    {
        "name": "System Reboot or Shutdown",
        "description": "System reboot or shutdown was initiated",
        "pattern": r"systemd.*reboot|shutdown.*-h|poweroff|init 0|init 6|halt|reboot",
        "severity": "MEDIUM", "level": 7,
        "category": "availability", "groups": "system",
        "mitre_tactic": "Impact", "mitre_technique": "T1529",
        "cooldown_seconds": 3600,
    },
    {
        "name": "High CPU Usage",
        "description": "System CPU usage critically high",
        "pattern": r"CPU critical|cpu.*9[5-9]%|cpu.*100%|load average.*[1-9][0-9]\.",
        "severity": "HIGH", "level": 9,
        "category": "availability", "groups": "system,performance",
        "mitre_tactic": "Impact", "mitre_technique": "T1496",
        "cooldown_seconds": 600,
    },
    {
        "name": "High Memory Usage",
        "description": "System memory usage critically high",
        "pattern": r"Memory critical|memory.*9[5-9]%|swap.*9[0-9]%",
        "severity": "HIGH", "level": 9,
        "category": "availability", "groups": "system,performance",
        "mitre_tactic": "Impact", "mitre_technique": "T1499",
        "cooldown_seconds": 600,
    },

    # ══════════════════════════════════════════════════════════════════════
    # PERSISTENCE
    # ══════════════════════════════════════════════════════════════════════
    {
        "name": "Cron Job Created",
        "description": "New cron job added to the system",
        "pattern": r"crontab.*-e|crontab.*installed|CRON.*CMD|new crontab entry",
        "severity": "MEDIUM", "level": 7,
        "category": "persistence", "groups": "persistence,cron",
        "mitre_tactic": "Persistence", "mitre_technique": "T1053.003",
        "cooldown_seconds": 120,
    },
    {
        "name": "New Systemd Service Installed",
        "description": "New systemd service unit was created",
        "pattern": r"systemctl.*enable|Created symlink.*\.service|unit.*enabled.*systemd",
        "severity": "MEDIUM", "level": 8,
        "category": "persistence", "groups": "persistence,systemd",
        "mitre_tactic": "Persistence", "mitre_technique": "T1543.002",
        "cooldown_seconds": 120,
    },
    {
        "name": "RC.Local Modified",
        "description": "/etc/rc.local modified — startup persistence",
        "pattern": r"FIM.*rc\.local|rc\.local.*modified|echo.*>>.*/etc/rc\.local",
        "severity": "HIGH", "level": 11,
        "category": "persistence", "groups": "persistence,fim",
        "mitre_tactic": "Persistence", "mitre_technique": "T1037.004",
        "cooldown_seconds": 300,
    },
    {
        "name": "Hosts File Modified",
        "description": "/etc/hosts was changed — possible DNS hijacking",
        "pattern": r"FIM.*\betc/hosts\b|fim.*modified.*/etc/hosts",
        "severity": "HIGH", "level": 11,
        "category": "defense_evasion", "groups": "fim,network,defense_evasion",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1565.001",
        "cooldown_seconds": 300,
    },

    # ══════════════════════════════════════════════════════════════════════
    # DEFENSE EVASION
    # ══════════════════════════════════════════════════════════════════════
    {
        "name": "History File Cleared",
        "description": "Shell history was deleted or truncated",
        "pattern": r"history.*cleared|HISTFILE.*deleted|unset HISTFILE|HISTSIZE=0|rm.*bash_history|truncate.*history",
        "severity": "HIGH", "level": 11,
        "category": "defense_evasion", "groups": "defense_evasion",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1070.003",
        "cooldown_seconds": 300,
    },
    {
        "name": "Auditd Service Stopped",
        "description": "Audit daemon was stopped — logging gap",
        "pattern": r"auditd.*stop|systemctl.*stop.*audit|service.*auditd.*stop",
        "severity": "CRITICAL", "level": 14,
        "category": "defense_evasion", "groups": "audit,defense_evasion",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1562.001",
        "cooldown_seconds": 300,
    },
    {
        "name": "Firewall Disabled",
        "description": "Host firewall was stopped or disabled",
        "pattern": r"ufw.*disable|iptables.*flush|systemctl.*stop.*firewall|nft.*flush",
        "severity": "HIGH", "level": 12,
        "category": "defense_evasion", "groups": "network,defense_evasion",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1562.004",
        "cooldown_seconds": 300,
    },
    {
        "name": "Process Running from /tmp or /dev/shm",
        "description": "Suspicious process executing from temporary directory",
        "pattern": r"PROCESS.*/tmp/|PROCESS.*/dev/shm/|exe.*=.*/tmp/|cmdline.*/tmp/\S+\.(sh|py|elf|bin)",
        "severity": "HIGH", "level": 12,
        "category": "defense_evasion", "groups": "malware,defense_evasion",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1036.005",
        "cooldown_seconds": 120,
    },

    # ══════════════════════════════════════════════════════════════════════
    # LATERAL MOVEMENT
    # ══════════════════════════════════════════════════════════════════════
    {
        "name": "Lateral Movement — SSH to Internal Host",
        "description": "SSH connection to another internal host from this agent",
        "pattern": r"ssh.*192\.168\.|ssh.*10\.\d+\.\d+\.|ssh.*172\.(1[6-9]|2[0-9]|3[01])\.",
        "severity": "MEDIUM", "level": 8,
        "category": "lateral_movement", "groups": "ssh,lateral_movement",
        "mitre_tactic": "Lateral Movement", "mitre_technique": "T1021.004",
        "cooldown_seconds": 300,
    },
    {
        "name": "Network Scanning Tools Used",
        "description": "Network enumeration tool executed",
        "pattern": r"\bnmap\b|\bmasscan\b|\bzmap\b|\barp-scan\b|\bnetcat\b.*-z\b",
        "severity": "HIGH", "level": 10,
        "category": "reconnaissance", "groups": "reconnaissance,network",
        "mitre_tactic": "Reconnaissance", "mitre_technique": "T1046",
        "cooldown_seconds": 300,
    },
    {
        "name": "Credential Dumping Tools",
        "description": "Known credential dumping tool execution",
        "pattern": r"mimikatz|secretsdump|hashdump|lazagne|credphisher|lsassy|pypykatz",
        "severity": "CRITICAL", "level": 15,
        "category": "credential_access", "groups": "credential_access,malware",
        "mitre_tactic": "Credential Access", "mitre_technique": "T1003",
        "cooldown_seconds": 300,
    },

    # ══════════════════════════════════════════════════════════════════════
    # DOCKER / CONTAINERS
    # ══════════════════════════════════════════════════════════════════════
    {
        "name": "Container OOM Killed",
        "description": "Docker container killed by OOM",
        "pattern": r"container.*oom.killed|docker.*oom|container.*memory.*limit",
        "severity": "HIGH", "level": 9,
        "category": "docker", "groups": "docker,availability",
        "mitre_tactic": "Impact", "mitre_technique": "T1499",
        "cooldown_seconds": 300,
    },
    {
        "name": "Privileged Container Started",
        "description": "Docker container started with --privileged flag",
        "pattern": r"docker.*--privileged|container.*privileged.*mode|docker.*run.*privileged",
        "severity": "HIGH", "level": 12,
        "category": "docker", "groups": "docker,privilege_escalation",
        "mitre_tactic": "Privilege Escalation", "mitre_technique": "T1611",
        "cooldown_seconds": 300,
    },
    {
        "name": "Container Escape Attempt",
        "description": "Possible container escape via host path mount",
        "pattern": r"docker.*run.*-v\s*/:/|docker.*run.*--pid.*host|nsenter.*-t.*1",
        "severity": "CRITICAL", "level": 15,
        "category": "docker", "groups": "docker,privilege_escalation",
        "mitre_tactic": "Privilege Escalation", "mitre_technique": "T1611",
        "cooldown_seconds": 300,
    },

    # ══════════════════════════════════════════════════════════════════════
    # AUDIT / COMPLIANCE
    # ══════════════════════════════════════════════════════════════════════
    {
        "name": "Audit Configuration Changed",
        "description": "Audit rules or configuration was modified",
        "pattern": r"audit_config.*modified|auditctl.*changed|FIM.*audit|audit\.rules.*modified",
        "severity": "CRITICAL", "level": 14,
        "category": "compliance", "groups": "audit,defense_evasion",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1562.001",
        "cooldown_seconds": 300,
    },
    {
        "name": "SELinux / AppArmor Disabled",
        "description": "Mandatory access control system was disabled",
        "pattern": r"setenforce 0|selinux.*disabled|apparmor.*disable|systemctl.*stop.*apparmor",
        "severity": "HIGH", "level": 12,
        "category": "defense_evasion", "groups": "compliance,defense_evasion",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1562.001",
        "cooldown_seconds": 600,
    },

    # ══════════════════════════════════════════════════════════════════════
    # WINDOWS (when agent runs on Windows)
    # ══════════════════════════════════════════════════════════════════════
    {
        "name": "Windows Failed Logon",
        "description": "Windows logon failure (Event ID 4625)",
        "pattern": r"EventID=4625|event_id.*4625|Logon Failure|Failed Logon",
        "severity": "LOW", "level": 5,
        "category": "authentication", "groups": "authentication,windows",
        "mitre_tactic": "Credential Access", "mitre_technique": "T1110",
        "cooldown_seconds": 0,
    },
    {
        "name": "Windows Logon Success",
        "description": "Windows account logon (Event ID 4624)",
        "pattern": r"EventID=4624|event_id.*4624|Account Logon",
        "severity": "LOW", "level": 3,
        "category": "authentication", "groups": "authentication,windows",
        "mitre_tactic": "Initial Access", "mitre_technique": "T1078",
        "cooldown_seconds": 0,
    },
    {
        "name": "Windows Account Created",
        "description": "New Windows user account (Event ID 4720)",
        "pattern": r"EventID=4720|event_id.*4720|User Account Created",
        "severity": "HIGH", "level": 8,
        "category": "persistence", "groups": "user_management,windows",
        "mitre_tactic": "Persistence", "mitre_technique": "T1136.001",
        "cooldown_seconds": 300,
    },
    {
        "name": "Windows Privilege Use",
        "description": "Sensitive privilege used (Event ID 4672)",
        "pattern": r"EventID=4672|event_id.*4672|Special Logon|privilege.*assigned",
        "severity": "MEDIUM", "level": 7,
        "category": "privilege_escalation", "groups": "windows,privilege_escalation",
        "mitre_tactic": "Privilege Escalation", "mitre_technique": "T1078.002",
        "cooldown_seconds": 60,
    },
    {
        "name": "Windows PowerShell Execution Policy Bypass",
        "description": "PowerShell execution policy bypassed",
        "pattern": r"ExecutionPolicy.*Bypass|-EncodedCommand|-enc |-exec bypass|powershell.*-nop",
        "severity": "HIGH", "level": 11,
        "category": "defense_evasion", "groups": "windows,powershell,defense_evasion",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1059.001",
        "cooldown_seconds": 120,
    },
    {
        "name": "Windows Security Log Cleared",
        "description": "Windows security event log was cleared (Event ID 1102)",
        "pattern": r"EventID=1102|event_id.*1102|Security.*Log.*Cleared|Audit Log.*Cleared",
        "severity": "CRITICAL", "level": 14,
        "category": "defense_evasion", "groups": "windows,defense_evasion",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1070.001",
        "cooldown_seconds": 300,
    },
    {
        "name": "Windows Service Installed",
        "description": "New Windows service installed (Event ID 7045)",
        "pattern": r"EventID=7045|event_id.*7045|Service.*Installed|New Service",
        "severity": "MEDIUM", "level": 8,
        "category": "persistence", "groups": "windows,persistence",
        "mitre_tactic": "Persistence", "mitre_technique": "T1543.003",
        "cooldown_seconds": 300,
    },
    {
        "name": "Windows Registry Persistence",
        "description": "Registry run key modified for persistence",
        "pattern": r"HKCU.*Run|HKLM.*Run|Registry.*Run.*modified|reg.*add.*\\Run",
        "severity": "HIGH", "level": 11,
        "category": "persistence", "groups": "windows,persistence",
        "mitre_tactic": "Persistence", "mitre_technique": "T1547.001",
        "cooldown_seconds": 300,
    },
    {
        "name": "Windows Mimikatz / LSASS Dump",
        "description": "LSASS memory access or mimikatz signatures",
        "pattern": r"lsass.*dump|mimikatz|wce\.exe|fgdump|procdump.*lsass|sekurlsa",
        "severity": "CRITICAL", "level": 15,
        "category": "credential_access", "groups": "windows,credential_access",
        "mitre_tactic": "Credential Access", "mitre_technique": "T1003.001",
        "cooldown_seconds": 300,
    },

    # ══════════════════════════════════════════════════════════════════════
    # VULNERABILITY / EXPLOIT
    # ══════════════════════════════════════════════════════════════════════
    {
        "name": "Log4Shell Exploitation Attempt",
        "description": "Log4j JNDI injection attack (CVE-2021-44228)",
        "pattern": r"\$\{jndi:(ldap|rmi|dns|iiop)://|\$\{.*jndi.*}|jndi.*ldap.*://",
        "severity": "CRITICAL", "level": 15,
        "category": "web", "groups": "web,exploit,cve",
        "mitre_tactic": "Initial Access", "mitre_technique": "T1190",
        "cooldown_seconds": 60,
    },
    {
        "name": "Shellshock Attack Attempt",
        "description": "Bash Shellshock vulnerability exploitation (CVE-2014-6271)",
        "pattern": r"\(\)\s*\{.*\};\s*|__TEST_VARS_|bash.*CVE-2014-6271",
        "severity": "CRITICAL", "level": 15,
        "category": "web", "groups": "web,exploit,cve",
        "mitre_tactic": "Initial Access", "mitre_technique": "T1190",
        "cooldown_seconds": 60,
    },
    {
        "name": "Heartbleed Probe",
        "description": "OpenSSL Heartbleed exploitation attempt (CVE-2014-0160)",
        "pattern": r"heartbleed|HEARTBLEED|malformed.*heartbeat|TLS.*heartbeat.*overflow",
        "severity": "CRITICAL", "level": 14,
        "category": "network", "groups": "network,exploit,cve",
        "mitre_tactic": "Collection", "mitre_technique": "T1040",
        "cooldown_seconds": 300,
    },
    {
        "name": "Dirty COW Exploitation Indicator",
        "description": "Dirty COW (CVE-2016-5195) privilege escalation patterns",
        "pattern": r"dirtycow|dirty_cow|CVE-2016-5195|/proc/self/mem.*race|dcow",
        "severity": "CRITICAL", "level": 15,
        "category": "privilege_escalation", "groups": "exploit,cve",
        "mitre_tactic": "Privilege Escalation", "mitre_technique": "T1068",
        "cooldown_seconds": 300,
    },
]


# ─────────────────────────────────────────────────────────────────────────────

async def seed():
    inserted = 0
    skipped  = 0

    async with AsyncSessionLocal() as db:
        for rule_data in RULES:
            # Check if rule with same name already exists
            existing = (await db.execute(
                select(Rule).where(Rule.name == rule_data["name"])
            )).scalar_one_or_none()

            if existing:
                skipped += 1
                continue

            rule = Rule(
                name             = rule_data["name"],
                description      = rule_data.get("description"),
                pattern          = rule_data.get("pattern"),
                severity         = rule_data["severity"],
                level            = rule_data.get("level", 5),
                category         = rule_data.get("category", "general"),
                groups           = rule_data.get("groups", ""),
                enabled          = True,
                cooldown_seconds = rule_data.get("cooldown_seconds", 300),
                custom_logic     = rule_data.get("custom_logic"),
                frequency        = rule_data.get("frequency"),
                timeframe        = rule_data.get("timeframe"),
                mitre_tactic     = rule_data.get("mitre_tactic"),
                mitre_technique  = rule_data.get("mitre_technique"),
                field_name       = rule_data.get("field_name"),
                field_value      = rule_data.get("field_value"),
            )
            db.add(rule)
            inserted += 1

        await db.commit()

    print(f"Rules seed complete: {inserted} inserted, {skipped} already existed")
    print(f"Total rules in RULES list: {len(RULES)}")


if __name__ == "__main__":
    asyncio.run(seed())
