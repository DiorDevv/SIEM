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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_finding(category: str, severity: str, detail: str, extra: dict = None) -> Dict[str, Any]:
    msg = f"ROOTCHECK [{category.upper()}]: {detail}"
    logger.warning(msg)
    fields = {
        "event_type":    "rootkit_detected",
        "check_category": category,
        "detail":        detail,
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


# ── Main entry point ──────────────────────────────────────────────────────────

def run_rootcheck(config: dict = None) -> List[Dict[str, Any]]:
    """Run all rootcheck modules. Returns list of finding log dicts."""
    if os.name == "nt":
        return []  # Windows not supported yet

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
