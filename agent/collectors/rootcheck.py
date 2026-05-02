"""
Rootcheck collector — Wazuh-style rootkit and anomaly detection.
Checks for:
  - Hidden processes (pid in /proc but not in ps output)
  - Suspicious kernel modules
  - SUID/SGID files in unexpected locations
  - Known rootkit files/directories
  - Suspicious /etc/ld.so.preload (LD_PRELOAD hijack)
  - Writable files in system directories
"""
import os
import re
import stat
import logging
import subprocess
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# ── Known rootkit indicators ──────────────────────────────────────────────────

KNOWN_ROOTKIT_FILES = [
    "/usr/lib32/libgcc_s.so",
    "/usr/bin/.sshd", "/usr/sbin/.sshd",
    "/dev/.udev/rules.d",
    "/etc/.hidden",
    "/tmp/.ICE-unix/.X11",
    "/lib/libproc.so",
    "/usr/lib/libpam.so",
    "/proc/kcore",          # suspicious if modified recently
    "/.sutemp",
    "/etc/rc.d/init.d/hdparm",
    "/usr/bin/lsdev",
    "/usr/bin/slay",
    "/usr/sbin/in.bnc",
    "/usr/lib/lidps1.so",
]

KNOWN_ROOTKIT_DIRS = [
    "/usr/src/.puta",
    "/.x11", "/tmp/.x11",
    "/dev/.hda",
    "/dev/fd0",
    "/var/adm/.profile",
]

SUSPICIOUS_LD_PRELOAD_LIBS = [
    "libprocesshider",
    "libhide",
    "LD_PRELOAD",
]

EXPECTED_SUID_FILES = {
    "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd",
    "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/newgrp",
    "/usr/bin/pkexec", "/usr/lib/openssh/ssh-keysign",
    "/bin/ping", "/bin/mount", "/bin/umount",
    "/usr/bin/crontab", "/usr/sbin/pppd",
}


# ── MITRE ATT&CK mapping ──────────────────────────────────────────────────────
_ROOTCHECK_MITRE: Dict[str, str] = {
    'ld_preload':       'T1574.006',  # Dynamic Linker Hijacking
    'rootkit_file':     'T1014',      # Rootkit
    'rootkit_dir':      'T1014',      # Rootkit
    'hidden_process':   'T1564.001',  # Hide Artifacts: Hidden Files
    'suid_file':        'T1548.001',  # Setuid and Setgid
    'kernel_module':    'T1215',      # Kernel Modules and Extensions
    'suspicious_cron':  'T1053.003',  # Scheduled Task: Cron
    'unexpected_port':  'T1049',      # System Network Connections Discovery
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_finding(category: str, severity: str, detail: str, extra: dict = None) -> Dict[str, Any]:
    msg = f"ROOTCHECK [{category.upper()}]: {detail}"
    logger.warning(msg)
    fields = {
        "event_type":       "rootkit_detected",
        "check_category":   category,
        "detail":           detail,
        "mitre_technique":  _ROOTCHECK_MITRE.get(category, 'T1014'),
    }
    if extra:
        fields.update(extra)
    return {
        "timestamp":     _now(),
        "level":         severity,
        "source":        "rootcheck",
        "message":       msg,
        "raw":           msg,
        "parsed_fields": fields,
    }


# ── Individual checks ─────────────────────────────────────────────────────────

def check_ld_preload() -> List[Dict[str, Any]]:
    findings = []
    preload = "/etc/ld.so.preload"
    if os.path.exists(preload):
        try:
            with open(preload) as f:
                content = f.read().strip()
            if content:
                findings.append(_make_finding(
                    "ld_preload", "CRITICAL",
                    f"/etc/ld.so.preload contains: {content[:200]}",
                    {"file_path": preload, "content": content},
                ))
        except Exception:
            pass
    return findings


def check_known_rootkit_files() -> List[Dict[str, Any]]:
    findings = []
    for path in KNOWN_ROOTKIT_FILES:
        if os.path.exists(path):
            try:
                st = os.stat(path)
                age = datetime.now().timestamp() - st.st_mtime
                findings.append(_make_finding(
                    "rootkit_file", "CRITICAL",
                    f"Known rootkit file found: {path} (size={st.st_size}, age={int(age)}s)",
                    {"file_path": path, "event_type": "hidden_file"},
                ))
            except Exception:
                pass
    for d in KNOWN_ROOTKIT_DIRS:
        if os.path.exists(d) and os.path.isdir(d):
            findings.append(_make_finding(
                "rootkit_dir", "CRITICAL",
                f"Known rootkit directory found: {d}",
                {"file_path": d, "event_type": "hidden_file"},
            ))
    return findings


def check_hidden_processes() -> List[Dict[str, Any]]:
    findings = []
    try:
        # Get PIDs from /proc
        proc_pids = set()
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                proc_pids.add(int(entry))

        # Get PIDs from ps
        result = subprocess.run(
            ["ps", "-e", "--no-headers", "-o", "pid"],
            capture_output=True, text=True, timeout=5
        )
        ps_pids = set()
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if line.isdigit():
                ps_pids.add(int(line))

        # PIDs in /proc but not in ps = potentially hidden
        hidden = proc_pids - ps_pids - {1}  # ignore PID 1 (init)
        for pid in hidden:
            # Verify it's still there
            proc_path = f"/proc/{pid}"
            if not os.path.exists(proc_path):
                continue
            try:
                with open(f"/proc/{pid}/cmdline", 'rb') as f:
                    cmdline = f.read().decode('utf-8', errors='replace').replace('\x00', ' ')
                findings.append(_make_finding(
                    "hidden_process", "CRITICAL",
                    f"Hidden process detected: PID={pid} cmd={cmdline[:100]}",
                    {"pid": pid, "cmdline": cmdline[:200], "event_type": "hidden_process"},
                ))
            except Exception:
                pass
    except Exception as e:
        logger.debug(f"Hidden process check error: {e}")
    return findings


def check_suid_files(scan_dirs: List[str] = None) -> List[Dict[str, Any]]:
    findings = []
    if scan_dirs is None:
        scan_dirs = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/tmp", "/var/tmp"]

    for directory in scan_dirs:
        if not os.path.isdir(directory):
            continue
        try:
            for fname in os.listdir(directory):
                fpath = os.path.join(directory, fname)
                try:
                    st = os.stat(fpath)
                    mode = st.st_mode
                    is_suid = bool(mode & stat.S_ISUID)
                    is_sgid = bool(mode & stat.S_ISGID)

                    if (is_suid or is_sgid) and fpath not in EXPECTED_SUID_FILES:
                        bit = "SUID" if is_suid else "SGID"
                        findings.append(_make_finding(
                            "suid_file", "HIGH",
                            f"Unexpected {bit} file: {fpath} (mode={oct(mode)})",
                            {
                                "file_path": fpath,
                                "mode": oct(mode),
                                "uid": st.st_uid,
                                "gid": st.st_gid,
                                "event_type": "fim_permissions_changed",
                            },
                        ))
                except (PermissionError, FileNotFoundError):
                    pass
        except PermissionError:
            pass
    return findings


def check_kernel_modules() -> List[Dict[str, Any]]:
    findings = []
    suspicious_patterns = [
        re.compile(r'hide|rootkit|hook|inject|sniff', re.I),
    ]
    try:
        result = subprocess.run(
            ["lsmod"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.strip().split("\n")[1:]:  # skip header
            parts = line.split()
            if not parts:
                continue
            mod_name = parts[0]
            for pat in suspicious_patterns:
                if pat.search(mod_name):
                    findings.append(_make_finding(
                        "kernel_module", "CRITICAL",
                        f"Suspicious kernel module loaded: {mod_name}",
                        {"module": mod_name, "event_type": "kernel_module_loaded"},
                    ))
    except Exception as e:
        logger.debug(f"Kernel module check error: {e}")
    return findings


def check_suspicious_cron() -> List[Dict[str, Any]]:
    findings = []
    cron_dirs = [
        "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
        "/etc/cron.monthly", "/etc/cron.weekly", "/var/spool/cron",
    ]
    suspicious = re.compile(r'(wget|curl|bash|/tmp|/dev/shm|nc |ncat|netcat|python.*-c|perl.*-e)', re.I)

    for cron_dir in cron_dirs:
        if not os.path.isdir(cron_dir):
            continue
        try:
            for fname in os.listdir(cron_dir):
                fpath = os.path.join(cron_dir, fname)
                if not os.path.isfile(fpath):
                    continue
                try:
                    with open(fpath) as f:
                        content = f.read()
                    for line in content.split("\n"):
                        if line.startswith("#"):
                            continue
                        if suspicious.search(line):
                            findings.append(_make_finding(
                                "suspicious_cron", "HIGH",
                                f"Suspicious cron entry in {fpath}: {line.strip()[:200]}",
                                {
                                    "file_path": fpath,
                                    "cron_line": line.strip()[:200],
                                    "event_type": "cron_job",
                                },
                            ))
                except (PermissionError, UnicodeDecodeError):
                    pass
        except PermissionError:
            pass
    return findings


def check_listening_ports() -> List[Dict[str, Any]]:
    """Detect new/unexpected listening ports."""
    findings = []
    EXPECTED_PORTS = {22, 80, 443, 8080, 8000, 3000, 5432, 9200, 6379, 6380}
    try:
        result = subprocess.run(
            ["ss", "-tlnp"], capture_output=True, text=True, timeout=5
        )
        port_re = re.compile(r':(\d+)\s+')
        for line in result.stdout.strip().split("\n")[1:]:
            m = port_re.search(line)
            if m:
                port = int(m.group(1))
                if port not in EXPECTED_PORTS and port < 1024:
                    findings.append(_make_finding(
                        "unexpected_port", "MEDIUM",
                        f"Unexpected privileged port listening: {port} — {line.strip()[:100]}",
                        {"port": port, "event_type": "network_connection"},
                    ))
    except Exception as e:
        logger.debug(f"Port check error: {e}")
    return findings


# ── Windows rootcheck ─────────────────────────────────────────────────────────

import sys as _sys

_WIN_SUSPICIOUS_DIRS = [
    r"C:\Windows\Temp",
    r"C:\Users\Public",
    r"C:\ProgramData",
]

_WIN_SUSPICIOUS_EXE_RE = re.compile(
    r'\.(exe|dll|bat|ps1|vbs|js|jse|wsf|hta|scr|pif|cpl)$', re.I
)


def _win_check_startup_dirs() -> List[Dict[str, Any]]:
    """Scan user startup folders for suspicious executables."""
    findings = []
    import os
    startup_paths = [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"),
    ]
    for path in startup_paths:
        if not os.path.isdir(path):
            continue
        try:
            for fname in os.listdir(path):
                fpath = os.path.join(path, fname)
                if _WIN_SUSPICIOUS_EXE_RE.search(fname):
                    findings.append(_make_finding(
                        "suspicious_cron", "HIGH",
                        f"Suspicious startup entry: {fpath}",
                        {"file_path": fpath, "event_type": "persistence_attempt",
                         "mitre_technique": "T1547.001"},
                    ))
        except PermissionError:
            pass
    return findings


def _win_check_temp_executables() -> List[Dict[str, Any]]:
    """Check Temp/Public dirs for executables (common dropper pattern)."""
    findings = []
    for base_dir in _WIN_SUSPICIOUS_DIRS:
        base_dir = os.path.expandvars(base_dir)
        if not os.path.isdir(base_dir):
            continue
        try:
            for fname in os.listdir(base_dir):
                if _WIN_SUSPICIOUS_EXE_RE.search(fname):
                    fpath = os.path.join(base_dir, fname)
                    try:
                        age = datetime.now().timestamp() - os.stat(fpath).st_mtime
                        if age < 86400:  # only flag files < 24h old
                            findings.append(_make_finding(
                                "rootkit_file", "HIGH",
                                f"Recent executable in suspicious location: {fpath}",
                                {"file_path": fpath, "age_seconds": int(age),
                                 "event_type": "suspicious_process",
                                 "mitre_technique": "T1204"},
                            ))
                    except Exception:
                        pass
        except PermissionError:
            pass
    return findings


def _win_check_defender_status() -> List[Dict[str, Any]]:
    """Check Windows Defender real-time protection status."""
    findings = []
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-Command",
             "(Get-MpComputerStatus).RealTimeProtectionEnabled"],
            capture_output=True, text=True, timeout=10,
        )
        if result.stdout.strip().lower() == "false":
            findings.append(_make_finding(
                "kernel_module", "CRITICAL",
                "Windows Defender real-time protection is DISABLED",
                {"event_type": "defense_evasion", "mitre_technique": "T1562.001"},
            ))
    except Exception:
        pass
    return findings


def _win_check_audit_policy() -> List[Dict[str, Any]]:
    """Check if critical audit categories are disabled."""
    findings = []
    try:
        result = subprocess.run(
            ["auditpol", "/get", "/category:*"],
            capture_output=True, text=True, timeout=10,
        )
        if "No Auditing" in result.stdout:
            categories = [
                line.split("No Auditing")[0].strip()
                for line in result.stdout.splitlines()
                if "No Auditing" in line
            ]
            if categories:
                findings.append(_make_finding(
                    "unexpected_port", "HIGH",
                    f"Audit policy disabled for: {', '.join(categories[:5])}",
                    {"disabled_categories": categories[:10],
                     "event_type": "defense_evasion",
                     "mitre_technique": "T1562.002"},
                ))
    except Exception:
        pass
    return findings


def _win_check_lsass_protection() -> List[Dict[str, Any]]:
    """Check if LSASS is running with Protected Process Light (PPL)."""
    findings = []
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Lsa",
        ) as key:
            val, _ = winreg.QueryValueEx(key, "RunAsPPL")
            if int(val) == 0:
                findings.append(_make_finding(
                    "ld_preload", "HIGH",
                    "LSASS RunAsPPL is disabled — credential dumping risk",
                    {"reg_key": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL",
                     "value": 0, "mitre_technique": "T1003.001"},
                ))
    except FileNotFoundError:
        findings.append(_make_finding(
            "ld_preload", "MEDIUM",
            "LSASS RunAsPPL not configured (should be 1 or 2)",
            {"reg_key": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
             "mitre_technique": "T1003.001"},
        ))
    except Exception:
        pass
    return findings


def _win_check_wdigest() -> List[Dict[str, Any]]:
    """Check if WDigest cleartext credential caching is enabled."""
    findings = []
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDIGEST",
        ) as key:
            val, _ = winreg.QueryValueEx(key, "UseLogonCredential")
            if int(val) == 1:
                findings.append(_make_finding(
                    "ld_preload", "CRITICAL",
                    "WDigest UseLogonCredential=1 — cleartext passwords in memory",
                    {"reg_key": r"HKLM\...\WDIGEST\UseLogonCredential",
                     "value": 1, "mitre_technique": "T1112"},
                ))
    except Exception:
        pass
    return findings


def run_windows_rootcheck() -> List[Dict[str, Any]]:
    """Windows-specific rootcheck: startup dirs, temp executables, security settings."""
    all_findings = []
    checks = [
        ("win_startup_dirs",     _win_check_startup_dirs),
        ("win_temp_executables", _win_check_temp_executables),
        ("win_defender",         _win_check_defender_status),
        ("win_audit_policy",     _win_check_audit_policy),
        ("win_lsass_ppl",        _win_check_lsass_protection),
        ("win_wdigest",          _win_check_wdigest),
    ]
    for name, fn in checks:
        try:
            findings = fn()
            if findings:
                logger.warning(f"Win-Rootcheck [{name}]: {len(findings)} finding(s)")
            all_findings.extend(findings)
        except Exception as e:
            logger.error(f"Win-Rootcheck [{name}] failed: {e}", exc_info=True)
    return all_findings


# ── macOS rootcheck ───────────────────────────────────────────────────────────

def _macos_check_sip() -> List[Dict[str, Any]]:
    """Check System Integrity Protection (SIP) status."""
    findings = []
    try:
        result = subprocess.run(
            ["csrutil", "status"], capture_output=True, text=True, timeout=5
        )
        if "disabled" in result.stdout.lower():
            findings.append(_make_finding(
                "kernel_module", "CRITICAL",
                "System Integrity Protection (SIP) is disabled — T1553.006",
                {"check": "sip_status", "output": result.stdout[:200],
                 "mitre_technique": "T1553.006"},
            ))
    except Exception:
        pass
    return findings


def _macos_check_gatekeeper() -> List[Dict[str, Any]]:
    """Check Gatekeeper status."""
    findings = []
    try:
        result = subprocess.run(
            ["spctl", "--status"], capture_output=True, text=True, timeout=5
        )
        if "disabled" in (result.stdout + result.stderr).lower():
            findings.append(_make_finding(
                "rootkit_file", "HIGH",
                "Gatekeeper is disabled — unsigned code can run freely",
                {"check": "gatekeeper", "mitre_technique": "T1553.001"},
            ))
    except Exception:
        pass
    return findings


def _macos_check_dyld_preload() -> List[Dict[str, Any]]:
    """Check for DYLD_INSERT_LIBRARIES environment variable (dylib injection)."""
    findings = []
    try:
        dyld = os.environ.get("DYLD_INSERT_LIBRARIES", "")
        if dyld:
            findings.append(_make_finding(
                "ld_preload", "CRITICAL",
                f"DYLD_INSERT_LIBRARIES set: {dyld[:200]} — dylib injection active",
                {"dylib_path": dyld[:500], "mitre_technique": "T1574.006"},
            ))
        # Also check common injection config files
        for path in ("/etc/launchd.conf", "/private/etc/launchd.conf"):
            if os.path.exists(path):
                try:
                    content = open(path).read()
                    if "DYLD_INSERT" in content:
                        findings.append(_make_finding(
                            "ld_preload", "CRITICAL",
                            f"DYLD_INSERT_LIBRARIES in {path}",
                            {"path": path, "mitre_technique": "T1574.006"},
                        ))
                except Exception:
                    pass
    except Exception:
        pass
    return findings


def _macos_check_launchd_persistence() -> List[Dict[str, Any]]:
    """Check LaunchAgents/LaunchDaemons for suspicious entries."""
    findings = []
    _SUSPICIOUS_LAUNCHD_RE = re.compile(
        r'(curl|wget|bash\s+-[ci]|python.*-c|nc\s+-[el]'
        r'|/tmp/|/var/tmp/|base64\s+-d'
        r'|osascript.*-e)',
        re.IGNORECASE,
    )
    dirs_to_check = [
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        os.path.expanduser("~/Library/LaunchAgents"),
    ]
    for directory in dirs_to_check:
        if not os.path.isdir(directory):
            continue
        for fname in os.listdir(directory):
            if not fname.endswith(".plist"):
                continue
            fpath = os.path.join(directory, fname)
            try:
                result = subprocess.run(
                    ["plutil", "-p", fpath],
                    capture_output=True, text=True, timeout=5
                )
                content = result.stdout
                if _SUSPICIOUS_LAUNCHD_RE.search(content):
                    findings.append(_make_finding(
                        "suspicious_cron", "HIGH",
                        f"Suspicious LaunchAgent/Daemon: {fpath}",
                        {"plist_path": fpath,
                         "content_preview": content[:300],
                         "mitre_technique": "T1543.001"},
                    ))
            except Exception:
                pass
    return findings


def _macos_check_login_items() -> List[Dict[str, Any]]:
    """Detect login items that execute scripts or binaries from suspicious paths."""
    findings = []
    _SUSP_PATHS = re.compile(r'(/tmp/|/var/tmp/|\.sh$|\.py$|base64)', re.I)
    try:
        result = subprocess.run(
            ["osascript", "-e",
             'tell application "System Events" to get the path of every login item'],
            capture_output=True, text=True, timeout=8,
        )
        for item in result.stdout.split(","):
            item = item.strip()
            if item and _SUSP_PATHS.search(item):
                findings.append(_make_finding(
                    "suspicious_cron", "HIGH",
                    f"Suspicious Login Item: {item}",
                    {"login_item": item, "mitre_technique": "T1547.011"},
                ))
    except Exception:
        pass
    return findings


def _macos_check_nvram() -> List[Dict[str, Any]]:
    """Check NVRAM for boot-args that weaken security (e.g., SIP bypass)."""
    findings = []
    try:
        result = subprocess.run(
            ["nvram", "boot-args"], capture_output=True, text=True, timeout=5
        )
        output = result.stdout.lower()
        dangerous_args = ["amfi_get_out_of_my_way", "cs_enforcement_disable",
                          "-no-csr", "rootless=0", "kext-dev-mode=1"]
        found = [a for a in dangerous_args if a in output]
        if found:
            findings.append(_make_finding(
                "kernel_module", "CRITICAL",
                f"Dangerous NVRAM boot-args detected: {', '.join(found)}",
                {"boot_args": output[:200], "dangerous": found,
                 "mitre_technique": "T1542.003"},
            ))
    except Exception:
        pass
    return findings


def run_macos_rootcheck() -> List[Dict[str, Any]]:
    """macOS-specific rootcheck: SIP, Gatekeeper, dylib injection, persistence."""
    all_findings = []
    checks = [
        ("macos_sip",           _macos_check_sip),
        ("macos_gatekeeper",    _macos_check_gatekeeper),
        ("macos_dyld_preload",  _macos_check_dyld_preload),
        ("macos_launchd",       _macos_check_launchd_persistence),
        ("macos_login_items",   _macos_check_login_items),
        ("macos_nvram",         _macos_check_nvram),
    ]
    for name, fn in checks:
        try:
            findings = fn()
            if findings:
                logger.warning(f"macOS-Rootcheck [{name}]: {len(findings)} finding(s)")
            all_findings.extend(findings)
        except Exception as e:
            logger.error(f"macOS-Rootcheck [{name}] failed: {e}", exc_info=True)
    return all_findings


# ── Main entry point ──────────────────────────────────────────────────────────

def run_rootcheck(config: dict = None) -> List[Dict[str, Any]]:
    """Run all rootcheck modules. Returns list of finding log dicts."""
    import sys
    if os.name == "nt":
        return run_windows_rootcheck()
    if sys.platform == "darwin":
        return run_macos_rootcheck()

    all_findings = []

    checks = [
        ("ld_preload",       check_ld_preload),
        ("rootkit_files",    check_known_rootkit_files),
        ("kernel_modules",   check_kernel_modules),
        ("suspicious_cron",  check_suspicious_cron),
        ("listening_ports",  check_listening_ports),
        # Hidden process check can be slow — skip in Docker
        # ("hidden_processes", check_hidden_processes),
        # SUID scan can be slow — skip by default
        # ("suid_files",       check_suid_files),
    ]

    for name, fn in checks:
        try:
            findings = fn()
            if findings:
                logger.warning(f"Rootcheck [{name}]: {len(findings)} finding(s)")
            all_findings.extend(findings)
        except Exception as e:
            logger.error(f"Rootcheck [{name}] failed: {e}", exc_info=True)

    logger.info(f"Rootcheck complete: {len(all_findings)} total findings")
    return all_findings
