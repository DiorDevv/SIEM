import re
from datetime import datetime
from typing import Optional, Dict, Any

SYSLOG_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)

AUTH_FAILED_SSH = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
AUTH_ACCEPTED_SSH = re.compile(r"Accepted \w+ for (\S+) from (\S+)")
SUDO_PATTERN = re.compile(r"sudo:\s+(\S+)\s+:.*COMMAND=(.*)")
UFW_PATTERN = re.compile(r"UFW BLOCK.*SRC=(\S+).*DST=(\S+)")


def parse_log_level(message: str) -> str:
    msg_lower = message.lower()
    if any(k in msg_lower for k in ("error", "err", "failed", "failure", "critical", "crit", "fatal")):
        return "ERROR"
    if any(k in msg_lower for k in ("warn", "warning")):
        return "WARNING"
    if any(k in msg_lower for k in ("debug",)):
        return "DEBUG"
    if any(k in msg_lower for k in ("segfault", "core dumped", "killed", "oom")):
        return "CRITICAL"
    return "INFO"


def parse_syslog_line(line: str) -> Dict[str, Any]:
    parsed: Dict[str, Any] = {}
    m = SYSLOG_PATTERN.match(line)
    if m:
        parsed["host"] = m.group("host")
        parsed["process"] = m.group("process")
        parsed["pid"] = m.group("pid")
        parsed["message_body"] = m.group("message")

        m2 = AUTH_FAILED_SSH.search(line)
        if m2:
            parsed["ssh_user"] = m2.group(1)
            parsed["ssh_src_ip"] = m2.group(2)
            parsed["event_type"] = "ssh_failed"

        m3 = AUTH_ACCEPTED_SSH.search(line)
        if m3:
            parsed["ssh_user"] = m3.group(1)
            parsed["ssh_src_ip"] = m3.group(2)
            parsed["event_type"] = "ssh_accepted"

        m4 = SUDO_PATTERN.search(line)
        if m4:
            parsed["sudo_user"] = m4.group(1)
            parsed["sudo_command"] = m4.group(2)
            parsed["event_type"] = "sudo"

        m5 = UFW_PATTERN.search(line)
        if m5:
            parsed["src_ip"] = m5.group(1)
            parsed["dst_ip"] = m5.group(2)
            parsed["event_type"] = "firewall_block"

    return parsed


def normalize_log(raw_log: dict) -> dict:
    message = raw_log.get("message", "")
    raw = raw_log.get("raw", message)
    level = raw_log.get("level") or parse_log_level(message)
    parsed = parse_syslog_line(raw or message)
    ts = raw_log.get("timestamp")
    if not ts:
        ts = datetime.utcnow().isoformat()
    return {
        "agent_id": raw_log.get("agent_id", ""),
        "timestamp": ts,
        "level": level.upper(),
        "source": raw_log.get("source", parsed.get("process", "unknown")),
        "message": message,
        "raw": raw,
        "parsed_fields": parsed,
    }
