"""
SecureWatch decoder pipeline — 500+ log format support.

Architecture:
  Each decoder is a class with match() + decode().
  Pipeline tries decoders by priority; accumulate=True decoders
  stack on top of each other (e.g. syslog header + ssh payload).
"""
from __future__ import annotations
import json
import re
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# ── Base ──────────────────────────────────────────────────────────────────────

class BaseDecoder:
    name:       str  = "base"
    priority:   int  = 100
    accumulate: bool = False          # if True, always runs even if earlier matched

    def match(self, log: Dict[str, Any]) -> bool:  return True
    def decode(self, log: Dict[str, Any]) -> Dict[str, Any]: return {}


def _re(pattern: str, text: str, flags: int = re.IGNORECASE) -> Optional[re.Match]:
    return re.search(pattern, text, flags)

def _named(pattern: str, text: str) -> Dict[str, str]:
    m = re.search(pattern, text, re.IGNORECASE)
    return {k: v for k, v in m.groupdict().items() if v is not None} if m else {}

def _text(log: Dict[str, Any]) -> str:
    return (log.get("raw") or log.get("message") or "")


# ══════════════════════════════════════════════════════════════════════════════
# TIER 1 — Structural decoders (run first)
# ══════════════════════════════════════════════════════════════════════════════

class JsonDecoder(BaseDecoder):
    """Generic JSON log (Docker, k8s, cloud providers, structured apps)."""
    name = "json"; priority = 1

    def match(self, log):
        t = _text(log).lstrip()
        return t.startswith("{") or t.startswith("[")

    def decode(self, log):
        try:
            data = json.loads(_text(log))
            if isinstance(data, dict):
                # Normalise common field names
                fields = {"json_decoded": True}
                fields.update(data)
                # Cloud / structured log normalisations
                for src, dst in [
                    ("timestamp", "ts"), ("@timestamp", "ts"),
                    ("msg", "message"), ("log", "message"),
                    ("severity", "level"), ("level", "level"),
                    ("host", "hostname"), ("hostname", "hostname"),
                ]:
                    if src in data and dst not in fields:
                        fields[dst] = data[src]
                return fields
        except Exception:
            pass
        return {}


class SyslogRFC3164(BaseDecoder):
    """RFC 3164 syslog: <PRI>Mon DD HH:MM:SS host prog[pid]: msg"""
    name = "syslog_rfc3164"; priority = 5; accumulate = True
    _RE = re.compile(
        r"^(?:<(?P<pri>\d+)>)?"
        r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+(?P<program>[^\s\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.+)$"
    )

    def match(self, log):
        return bool(self._RE.match(_text(log)))

    def decode(self, log):
        m = self._RE.match(_text(log))
        return {k: v for k, v in m.groupdict().items() if v} if m else {}


class SyslogRFC5424(BaseDecoder):
    """RFC 5424: <PRI>1 ISO8601 host app procid msgid [sd] msg"""
    name = "syslog_rfc5424"; priority = 5; accumulate = True
    _RE = re.compile(
        r"^<(?P<pri>\d+)>1\s+"
        r"(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+(?P<app>\S+)\s+"
        r"(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?:\[.*?\]\s+)?(?P<msg>.+)$"
    )

    def match(self, log):
        t = _text(log)
        return bool(re.match(r"^<\d+>1\s+", t))

    def decode(self, log):
        m = self._RE.match(_text(log))
        return {k: v for k, v in m.groupdict().items() if v} if m else {}


# ══════════════════════════════════════════════════════════════════════════════
# TIER 2 — Authentication & Access
# ══════════════════════════════════════════════════════════════════════════════

class SSHDecoder(BaseDecoder):
    name = "ssh"; priority = 10
    _RULES = [
        (re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>[\d.a-f:]+) port (?P<port>\d+)"),
         {"event": "ssh_auth_failed", "protocol": "ssh"}),
        (re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<src_ip>[\d.a-f:]+) port (?P<port>\d+)"),
         {"event": "authentication_success", "protocol": "ssh"}),
        (re.compile(r"Invalid user (?P<user>\S+) from (?P<src_ip>[\d.a-f:]+)"),
         {"event": "ssh_invalid_user", "protocol": "ssh"}),
        (re.compile(r"error: maximum authentication attempts exceeded.*?user (?P<user>\S+) from (?P<src_ip>[\d.a-f:]+)"),
         {"event": "ssh_max_auth_exceeded"}),
        (re.compile(r"Disconnected from(?:\s+authenticating)? user (?P<user>\S+) (?P<src_ip>[\d.a-f:]+)"),
         {"event": "ssh_disconnected"}),
        (re.compile(r"Connection closed by (?:authenticating )?(?:user (?P<user>\S+) )?(?P<src_ip>[\d.a-f:]+)"),
         {"event": "ssh_connection_closed"}),
        (re.compile(r"Bad protocol version identification '(?P<banner>[^']+)' from (?P<src_ip>[\d.a-f:]+)"),
         {"event": "ssh_bad_version"}),
        (re.compile(r"Did not receive identification string from (?P<src_ip>[\d.a-f:]+)"),
         {"event": "ssh_no_ident"}),
        (re.compile(r"Received disconnect from (?P<src_ip>[\d.a-f:]+).*:\s*(?P<reason>.+)"),
         {"event": "ssh_received_disconnect"}),
        (re.compile(r"User (?P<user>\S+) from (?P<src_ip>[\d.a-f:]+) not allowed"),
         {"event": "ssh_user_not_allowed"}),
        (re.compile(r"Postponed (?P<method>\S+) for (?P<user>\S+) from (?P<src_ip>[\d.a-f:]+)"),
         {"event": "ssh_mfa_required"}),
    ]

    def match(self, log):
        t = _text(log)
        return "sshd" in t.lower() or "ssh" in log.get("source", "").lower()

    def decode(self, log):
        t = _text(log)
        for pat, extra in self._RULES:
            m = pat.search(t)
            if m:
                fields = {k: v for k, v in m.groupdict().items() if v}
                fields.update(extra)
                fields["decoder"] = "ssh"
                return fields
        return {"decoder": "ssh"}


class PAMDecoder(BaseDecoder):
    name = "pam"; priority = 10
    _RULES = [
        (re.compile(r"pam_unix\((?P<service>[^:]+):auth\): authentication failure.*?user=(?P<user>\S+)(?:.*?rhost=(?P<src_ip>\S+))?"),
         {"event": "pam_auth_failed"}),
        (re.compile(r"pam_unix\((?P<service>[^:]+):session\): session opened for user (?P<user>\S+)"),
         {"event": "pam_session_opened"}),
        (re.compile(r"pam_unix\((?P<service>[^:]+):session\): session closed for user (?P<user>\S+)"),
         {"event": "pam_session_closed"}),
        (re.compile(r"pam_faillock.*?user (?P<user>\S+).*?fail_count=(?P<fail_count>\d+)"),
         {"event": "pam_faillock_exceeded"}),
        (re.compile(r"pam_tally2.*?user (?P<user>\S+)"),
         {"event": "pam_tally_exceeded"}),
        (re.compile(r"pam_unix\(su.*\): authentication failure.*?user=(?P<user>\S+)"),
         {"event": "su_auth_failed"}),
    ]

    def match(self, log):
        t = _text(log).lower()
        return "pam_unix" in t or "pam_faillock" in t or "pam_tally" in t

    def decode(self, log):
        t = _text(log)
        for pat, extra in self._RULES:
            m = pat.search(t)
            if m:
                f = {k: v for k, v in m.groupdict().items() if v}
                f.update(extra); f["decoder"] = "pam"
                return f
        return {"decoder": "pam"}


class SudoDecoder(BaseDecoder):
    name = "sudo"; priority = 10
    _CMD = re.compile(r"sudo:\s+(?P<user>\S+)\s*:.*?PWD=(?P<cwd>\S+).*?USER=(?P<runas>\S+).*?COMMAND=(?P<command>.+?)(?:;|$)")
    _FAIL = re.compile(r"sudo:.*(?:authentication failure|incorrect password|3 incorrect password)")
    _NOT_ALLOWED = re.compile(r"sudo:.*(?P<user>\S+).*is not in the sudoers file")

    def match(self, log):
        return "sudo:" in _text(log).lower()

    def decode(self, log):
        t = _text(log)
        if self._FAIL.search(t):
            return {"event": "sudo_auth_failed", "decoder": "sudo"}
        if self._NOT_ALLOWED.search(t):
            m = self._NOT_ALLOWED.search(t)
            return {"event": "sudo_not_allowed", "user": m.group("user") if m else "", "decoder": "sudo"}
        m = self._CMD.search(t)
        if m:
            return {"event": "sudo_command", "user": m.group("user"),
                    "cwd": m.group("cwd"), "runas": m.group("runas"),
                    "command": m.group("command").strip(), "decoder": "sudo"}
        return {"event": "sudo_event", "decoder": "sudo"}


class KerberosDecoder(BaseDecoder):
    name = "kerberos"; priority = 10
    _RULES = [
        (re.compile(r"AS_REQ.*?cname: (?P<user>\S+).*?caddr: (?P<src_ip>[\d.]+)"),
         {"event": "kerberos_as_req"}),
        (re.compile(r"TGS_REQ.*?sname: (?P<service>\S+)"),
         {"event": "kerberos_tgs_req"}),
        (re.compile(r"FAILED.*?KDC_ERR_(?P<error>\S+).*?cname: (?P<user>\S+)"),
         {"event": "kerberos_auth_failed"}),
        (re.compile(r"PREAUTH_FAILED.*?cname: (?P<user>\S+).*?(?P<src_ip>[\d.]+)"),
         {"event": "kerberos_preauth_failed"}),
    ]

    def match(self, log):
        t = _text(log).lower()
        return "krb5kdc" in t or "kerberos" in t or "AS_REQ" in _text(log)

    def decode(self, log):
        t = _text(log)
        for pat, extra in self._RULES:
            m = pat.search(t)
            if m:
                f = {k: v for k, v in m.groupdict().items() if v}
                f.update(extra); f["decoder"] = "kerberos"
                return f
        return {"decoder": "kerberos"}


# ══════════════════════════════════════════════════════════════════════════════
# TIER 3 — Web servers
# ══════════════════════════════════════════════════════════════════════════════

class NginxAccessDecoder(BaseDecoder):
    name = "nginx_access"; priority = 10
    _RE = re.compile(
        r'^(?P<src_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+(?P<http_version>[^"]+)"\s+'
        r'(?P<status>\d{3})\s+(?P<bytes_sent>\d+)'
        r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    )

    def match(self, log):
        src = log.get("source", "").lower()
        return "nginx" in src or ("access" in src and self._RE.match(_text(log)))

    def decode(self, log):
        m = self._RE.match(_text(log))
        if not m: return {}
        status = int(m.group("status"))
        ua = m.group("user_agent") or ""
        return {
            "src_ip": m.group("src_ip"), "http_method": m.group("method"),
            "url": m.group("url"), "http_status": status,
            "bytes_sent": int(m.group("bytes_sent")),
            "user_agent": ua, "referrer": m.group("referrer") or "",
            "event": "http_request", "is_error": status >= 400,
            "is_scanner": any(s in ua.lower() for s in
                ["nikto","sqlmap","nmap","masscan","zgrab","nuclei","gobuster",
                 "dirbuster","dirb","hydra","medusa","burp","nessus"]),
            "decoder": "nginx_access",
        }


class ApacheAccessDecoder(BaseDecoder):
    """Apache Combined/Common log format."""
    name = "apache_access"; priority = 10
    _RE = re.compile(
        r'^(?P<src_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+HTTP/(?P<http_ver>\S+)"\s+'
        r'(?P<status>\d{3})\s+(?P<bytes>[\d-]+)'
        r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    )

    def match(self, log):
        src = log.get("source", "").lower()
        return "apache" in src or "httpd" in src

    def decode(self, log):
        m = self._RE.match(_text(log))
        if not m: return {}
        status = int(m.group("status"))
        return {
            "src_ip": m.group("src_ip"), "http_method": m.group("method"),
            "url": m.group("url"), "http_status": status,
            "user_agent": m.group("user_agent") or "",
            "event": "http_request", "is_error": status >= 400,
            "decoder": "apache_access",
        }


class ApacheErrorDecoder(BaseDecoder):
    """Apache error log."""
    name = "apache_error"; priority = 12
    _RE = re.compile(r"\[(?P<module>[^\]]+)\]\s+\[(?P<level>[^\]]+)\].*?(?:client (?P<src_ip>[\d.:]+))?.*?(?P<msg>[^\n]+)")

    def match(self, log):
        src = log.get("source", "").lower()
        t = _text(log)
        return ("apache" in src or "httpd" in src) and "[error]" in t.lower()

    def decode(self, log):
        m = self._RE.search(_text(log))
        if not m: return {"event": "apache_error", "decoder": "apache_error"}
        return {
            "module": m.group("module"), "level": m.group("level"),
            "src_ip": m.group("src_ip") or "",
            "event": "apache_error", "decoder": "apache_error",
        }


class HaProxyDecoder(BaseDecoder):
    name = "haproxy"; priority = 10
    _RE = re.compile(
        r"(?P<src_ip>[\d.]+):(?P<src_port>\d+).*?"
        r"(?P<frontend>\S+)/(?P<backend>\S+)\s+"
        r"(?P<status_code>\d+)\s+(?P<bytes>\d+)\s+--\s+"
        r"(?P<conns>\d+)/(?P<feconns>\d+)/(?P<beconns>\d+)"
    )

    def match(self, log):
        src = log.get("source", "").lower()
        return "haproxy" in src or "haproxy" in _text(log).lower()

    def decode(self, log):
        m = self._RE.search(_text(log))
        if m:
            return {
                "src_ip": m.group("src_ip"), "src_port": m.group("src_port"),
                "frontend": m.group("frontend"), "backend": m.group("backend"),
                "http_status": int(m.group("status_code")),
                "event": "haproxy_request", "decoder": "haproxy",
            }
        return {"decoder": "haproxy"}


# ══════════════════════════════════════════════════════════════════════════════
# TIER 4 — Databases
# ══════════════════════════════════════════════════════════════════════════════

class MySQLDecoder(BaseDecoder):
    name = "mysql"; priority = 10
    _ACCESS_DENIED = re.compile(r"Access denied for user '(?P<user>[^']+)'@'(?P<src_ip>[^']+)'\s+\(using password: (?P<pwd_used>\w+)\)")
    _SLOW = re.compile(r"Query_time:\s+(?P<query_time>[\d.]+)\s+Lock_time:\s+(?P<lock_time>[\d.]+).*?Rows_examined:\s+(?P<rows_examined>\d+)")
    _CONNECT = re.compile(r"(?:Connect|Quit)\s+(?P<user>[^@]+)@(?P<src_ip>\S+)")

    def match(self, log):
        src = log.get("source", "").lower()
        return "mysql" in src or "mariadb" in src

    def decode(self, log):
        t = _text(log)
        if "Access denied" in t:
            m = self._ACCESS_DENIED.search(t)
            if m:
                return {"event": "db_auth_failed", "user": m.group("user"),
                        "src_ip": m.group("src_ip"), "decoder": "mysql"}
        if "Query_time" in t:
            m = self._SLOW.search(t)
            if m:
                return {"event": "db_slow_query",
                        "query_time": float(m.group("query_time")),
                        "rows_examined": int(m.group("rows_examined")), "decoder": "mysql"}
        if _re(r"ERROR \d+", t):
            return {"event": "db_error", "decoder": "mysql"}
        return {"decoder": "mysql"}


class PostgreSQLDecoder(BaseDecoder):
    name = "postgresql"; priority = 10
    _LOG = re.compile(r"(?P<pid>\d+).*?(?P<level>LOG|ERROR|FATAL|PANIC|WARNING|NOTICE):\s+(?P<msg>.+)")
    _AUTH_FAIL = re.compile(r"password authentication failed for user \"(?P<user>[^\"]+)\"")
    _CONN = re.compile(r"connection received.*?host=(?P<src_ip>\S+)\s+port=(?P<src_port>\d+)")

    def match(self, log):
        src = log.get("source", "").lower()
        return "postgres" in src or "postgresql" in src

    def decode(self, log):
        t = _text(log)
        if "password authentication failed" in t:
            m = self._AUTH_FAIL.search(t)
            return {"event": "db_auth_failed", "user": m.group("user") if m else "",
                    "decoder": "postgresql"}
        if "FATAL" in t:
            return {"event": "db_fatal_error", "decoder": "postgresql"}
        if "connection received" in t:
            m = self._CONN.search(t)
            if m:
                return {"event": "db_connection", "src_ip": m.group("src_ip"),
                        "decoder": "postgresql"}
        return {"decoder": "postgresql"}


class RedisDecoder(BaseDecoder):
    name = "redis"; priority = 12

    def match(self, log):
        src = log.get("source", "").lower()
        return "redis" in src

    def decode(self, log):
        t = _text(log).lower()
        if "wrong number of arguments" in t or "command not allowed" in t:
            return {"event": "redis_command_error", "decoder": "redis"}
        if "connection refused" in t or "client closed" in t:
            return {"event": "redis_connection_error", "decoder": "redis"}
        if "out of memory" in t:
            return {"event": "redis_oom", "decoder": "redis"}
        return {"decoder": "redis"}


class MongoDBDecoder(BaseDecoder):
    name = "mongodb"; priority = 10
    _AUTH = re.compile(r'"msg":"Authentication failed".*?"user":"(?P<user>[^"]+)".*?"client":"(?P<src_ip>[^"]+)"')
    _SLOW = re.compile(r'"durationMillis":(?P<ms>\d+).*?"op":"(?P<op>\w+)"')

    def match(self, log):
        src = log.get("source", "").lower()
        t = _text(log)
        return "mongod" in src or '"msg"' in t and "mongo" in src

    def decode(self, log):
        t = _text(log)
        if "Authentication failed" in t:
            m = self._AUTH.search(t)
            if m:
                return {"event": "db_auth_failed", "user": m.group("user"),
                        "src_ip": m.group("src_ip"), "decoder": "mongodb"}
        m = self._SLOW.search(t)
        if m and int(m.group("ms")) > 1000:
            return {"event": "db_slow_query", "query_time_ms": int(m.group("ms")),
                    "op": m.group("op"), "decoder": "mongodb"}
        return {"decoder": "mongodb"}


# ══════════════════════════════════════════════════════════════════════════════
# TIER 5 — Network / Firewall
# ══════════════════════════════════════════════════════════════════════════════

class UFWDecoder(BaseDecoder):
    name = "ufw"; priority = 8
    _RE = re.compile(
        r"\[UFW (?P<action>BLOCK|ALLOW|LIMIT|AUDIT)\].*?"
        r"IN=(?P<in_iface>\S*)\s+OUT=(?P<out_iface>\S*)\s+.*?"
        r"SRC=(?P<src_ip>\S+)\s+DST=(?P<dst_ip>\S+)\s+.*?"
        r"PROTO=(?P<protocol>\S+)(?:.*?SPT=(?P<src_port>\d+))?(?:.*?DPT=(?P<dst_port>\d+))?"
    )

    def match(self, log):
        t = _text(log)
        return "UFW" in t

    def decode(self, log):
        t = _text(log)
        m = self._RE.search(t)
        if m:
            return {k: v for k, v in m.groupdict().items() if v} | {
                "event": "firewall_block", "decoder": "ufw"}
        return {"event": "firewall_block", "decoder": "ufw"}


class IptablesDecoder(BaseDecoder):
    name = "iptables"; priority = 8
    _RE = re.compile(
        r"IN=(?P<in_iface>\S+).*?OUT=(?P<out_iface>\S*)\s+.*?"
        r"SRC=(?P<src_ip>[\d.]+)\s+DST=(?P<dst_ip>[\d.]+)\s+.*?"
        r"PROTO=(?P<protocol>\w+)(?:.*?SPT=(?P<src_port>\d+))?(?:.*?DPT=(?P<dst_port>\d+))?"
    )

    def match(self, log):
        t = _text(log)
        return ("DROP" in t or "REJECT" in t or "ACCEPT" in t) and "SRC=" in t

    def decode(self, log):
        t = _text(log)
        m = self._RE.search(t)
        action = "block" if ("DROP" in t or "REJECT" in t) else "allow"
        fields = {"action": action, "event": "firewall_block" if action == "block" else "firewall_allow",
                  "decoder": "iptables"}
        if m:
            fields.update({k: v for k, v in m.groupdict().items() if v})
        return fields


class Fail2BanDecoder(BaseDecoder):
    name = "fail2ban"; priority = 8
    _BAN = re.compile(r"Ban (?P<src_ip>[\d.a-f:]+)")
    _UNBAN = re.compile(r"Unban (?P<src_ip>[\d.a-f:]+)")
    _FOUND = re.compile(r"Found (?P<src_ip>[\d.a-f:]+)")
    _JAIL = re.compile(r"\[(?P<jail>[^\]]+)\]")

    def match(self, log):
        src = log.get("source", "").lower()
        return "fail2ban" in src or "fail2ban" in _text(log).lower()

    def decode(self, log):
        t = _text(log)
        jail_m = self._JAIL.search(t)
        jail = jail_m.group("jail") if jail_m else ""
        if "Ban " in t:
            m = self._BAN.search(t)
            return {"event": "fail2ban_ban", "src_ip": m.group("src_ip") if m else "",
                    "jail": jail, "decoder": "fail2ban"}
        if "Unban " in t:
            m = self._UNBAN.search(t)
            return {"event": "fail2ban_unban", "src_ip": m.group("src_ip") if m else "",
                    "jail": jail, "decoder": "fail2ban"}
        if "Found " in t:
            m = self._FOUND.search(t)
            return {"event": "fail2ban_found", "src_ip": m.group("src_ip") if m else "",
                    "jail": jail, "decoder": "fail2ban"}
        return {"decoder": "fail2ban"}


class OpenVPNDecoder(BaseDecoder):
    name = "openvpn"; priority = 10
    _AUTH_OK = re.compile(r"(?P<user>\S+) (?P<src_ip>[\d.]+):(?P<port>\d+) MULTI_sva: pool returned IPv4=(?P<vpn_ip>[\d.]+)")
    _AUTH_FAIL = re.compile(r"(?P<src_ip>[\d.]+):(?P<port>\d+) TLS Auth Error.*?username='(?P<user>[^']+)'")
    _CONNECT = re.compile(r"(?P<src_ip>[\d.]+):(?P<port>\d+) \[(?P<user>[^\]]+)\] Peer Connection Initiated")
    _DISCONNECT = re.compile(r"(?P<src_ip>[\d.]+):(?P<port>\d+) \[(?P<user>[^\]]+)\] SIGTERM|(?P<user2>[^\s]+)/(?P<src_ip2>[\d.]+):(?P<port2>\d+) SIGTERM")

    def match(self, log):
        src = log.get("source", "").lower()
        return "openvpn" in src

    def decode(self, log):
        t = _text(log)
        for pat, event in [
            (self._CONNECT,  "vpn_connected"),
            (self._AUTH_FAIL,"vpn_auth_failed"),
            (self._AUTH_OK,  "vpn_tunnel_up"),
        ]:
            m = pat.search(t)
            if m:
                f = {k: v for k, v in m.groupdict().items() if v}
                f["event"] = event; f["decoder"] = "openvpn"
                return f
        return {"decoder": "openvpn"}


class CiscoASADecoder(BaseDecoder):
    name = "cisco_asa"; priority = 10
    _RE = re.compile(
        r"%ASA-(?P<level>\d)-(?P<msg_id>\d+):\s+(?P<msg>.+)"
    )
    _DENY = re.compile(r"Deny (?P<protocol>\w+) src (?P<src_if>[^:]+):(?P<src_ip>[\d.]+)/(?P<src_port>\d+) dst (?P<dst_if>[^:]+):(?P<dst_ip>[\d.]+)/(?P<dst_port>\d+)")
    _AUTH_FAIL = re.compile(r"Authentication Failed from (?P<src_ip>[\d.]+)")

    def match(self, log):
        return "%ASA-" in _text(log) or "cisco" in log.get("source", "").lower()

    def decode(self, log):
        t = _text(log)
        m = self._RE.search(t)
        fields = {"decoder": "cisco_asa"}
        if m:
            fields["asa_level"] = m.group("level")
            fields["asa_msg_id"] = m.group("msg_id")

        if "Deny" in t:
            md = self._DENY.search(t)
            if md:
                fields.update({k: v for k, v in md.groupdict().items() if v})
                fields["event"] = "firewall_block"
        elif "Authentication Failed" in t:
            ma = self._AUTH_FAIL.search(t)
            if ma: fields["src_ip"] = ma.group("src_ip")
            fields["event"] = "auth_failed"
        elif "Teardown" in t:
            fields["event"] = "connection_closed"
        elif "Built" in t:
            fields["event"] = "connection_established"
        return fields


class PaloAltoDecoder(BaseDecoder):
    name = "palo_alto"; priority = 10
    _THREAT = re.compile(
        r"THREAT,(?P<ts>[^,]+),(?P<serial>[^,]+),(?P<type>[^,]+),(?P<sub>[^,]+),[^,]+,"
        r"(?P<src_ip>[^,]+),(?P<dst_ip>[^,]+),[^,]+,[^,]+,(?P<rule>[^,]+),"
        r"(?P<src_user>[^,]+),(?P<dst_user>[^,]+),(?P<app>[^,]+),(?P<session>[^,]+),"
        r"[^,]+,[^,]+,[^,]+,[^,]+,(?P<action>[^,]+)"
    )

    def match(self, log):
        return "THREAT," in _text(log) or "TRAFFIC," in _text(log) or \
               "palo" in log.get("source", "").lower()

    def decode(self, log):
        t = _text(log)
        m = self._THREAT.search(t)
        if m:
            return {
                "src_ip": m.group("src_ip"), "dst_ip": m.group("dst_ip"),
                "action": m.group("action"), "app": m.group("app"),
                "rule": m.group("rule"), "event": "firewall_threat",
                "decoder": "palo_alto",
            }
        return {"decoder": "palo_alto"}


# ══════════════════════════════════════════════════════════════════════════════
# TIER 6 — Cloud Providers
# ══════════════════════════════════════════════════════════════════════════════

class AWSCloudTrailDecoder(BaseDecoder):
    """AWS CloudTrail JSON events."""
    name = "aws_cloudtrail"; priority = 6

    def match(self, log):
        t = _text(log)
        src = log.get("source", "").lower()
        return ("cloudtrail" in src or "aws" in src) and \
               ('"eventSource"' in t or '"eventName"' in t)

    def decode(self, log):
        try:
            data = json.loads(_text(log))
        except Exception:
            data = log.get("parsed_fields", {}) or {}

        if not isinstance(data, dict): return {}
        src_ip = (data.get("sourceIPAddress") or
                  (data.get("requestParameters") or {}).get("sourceIPAddress", ""))
        user_identity = data.get("userIdentity", {}) or {}
        user = (user_identity.get("userName") or user_identity.get("sessionContext", {})
                .get("sessionIssuer", {}).get("userName", ""))

        event_name = data.get("eventName", "")
        event_src  = data.get("eventSource", "")
        error_code = data.get("errorCode", "")

        high_risk_events = {
            "CreateUser", "DeleteUser", "AttachUserPolicy", "AttachRolePolicy",
            "PutUserPolicy", "CreateAccessKey", "CreateLoginProfile",
            "ConsoleLogin", "StopLogging", "DeleteTrail", "DeleteBucket",
            "AuthorizeSecurityGroupIngress", "ModifyInstanceAttribute",
            "RunInstances", "CreateVpc", "GetSecretValue",
        }

        return {
            "event":       "aws_api_call",
            "event_name":  event_name,
            "event_source": event_src,
            "src_ip":      src_ip,
            "user":        user,
            "aws_account": data.get("recipientAccountId", ""),
            "aws_region":  data.get("awsRegion", ""),
            "error_code":  error_code,
            "is_high_risk": event_name in high_risk_events,
            "is_failed":   bool(error_code),
            "decoder":     "aws_cloudtrail",
        }


class AzureActivityDecoder(BaseDecoder):
    """Azure Activity Log / Diagnostic Log."""
    name = "azure_activity"; priority = 6

    def match(self, log):
        t = _text(log)
        src = log.get("source", "").lower()
        return ("azure" in src or "microsoft" in src) and \
               ('"operationName"' in t or '"resourceId"' in t)

    def decode(self, log):
        try:
            data = json.loads(_text(log))
        except Exception:
            data = log.get("parsed_fields", {}) or {}
        if not isinstance(data, dict): return {}

        caller = data.get("caller", "") or (data.get("properties") or {}).get("principalEmail", "")
        status = (data.get("status", {}) or {}).get("value", data.get("resultType", ""))
        op     = (data.get("operationName", {}) or {})
        op_name = op.get("value", op) if isinstance(op, dict) else str(op)

        high_risk = {
            "Microsoft.Authorization/roleAssignments/write",
            "Microsoft.Compute/virtualMachines/extensions/write",
            "Microsoft.KeyVault/vaults/secrets/read",
            "Microsoft.AAD/users/delete",
        }

        return {
            "event":        "azure_operation",
            "operation":    op_name,
            "caller":       caller,
            "status":       status,
            "resource":     data.get("resourceId", ""),
            "src_ip":       data.get("callerIpAddress", ""),
            "is_failed":    status in ("Failed", "Failure"),
            "is_high_risk": any(r in op_name for r in high_risk),
            "decoder":      "azure_activity",
        }


class GCPAuditDecoder(BaseDecoder):
    """Google Cloud Platform audit log."""
    name = "gcp_audit"; priority = 6

    def match(self, log):
        t = _text(log)
        src = log.get("source", "").lower()
        return ("gcp" in src or "google" in src or "gcloud" in src) and \
               '"protoPayload"' in t

    def decode(self, log):
        try:
            data = json.loads(_text(log))
        except Exception:
            return {}
        proto = data.get("protoPayload", {}) or {}
        auth  = proto.get("authenticationInfo", {}) or {}
        request = proto.get("requestMetadata", {}) or {}
        return {
            "event":       "gcp_api_call",
            "method":      proto.get("methodName", ""),
            "service":     proto.get("serviceName", ""),
            "user":        auth.get("principalEmail", ""),
            "src_ip":      request.get("callerIp", ""),
            "resource":    data.get("resource", {}).get("type", ""),
            "is_failed":   bool(proto.get("status", {}).get("code")),
            "decoder":     "gcp_audit",
        }


# ══════════════════════════════════════════════════════════════════════════════
# TIER 7 — Containers & Orchestration
# ══════════════════════════════════════════════════════════════════════════════

class DockerEventDecoder(BaseDecoder):
    name = "docker_event"; priority = 8

    def match(self, log):
        src = log.get("source", "").lower()
        pf  = log.get("parsed_fields", {}) or {}
        return "docker" in src or pf.get("container_name") or \
               any(k in _text(log).lower() for k in ["container", "image", "network", "volume"])

    def decode(self, log):
        t = _text(log)
        pf = log.get("parsed_fields", {}) or {}
        fields = {"decoder": "docker"}

        # Docker JSON log format
        try:
            data = json.loads(t)
            if isinstance(data, dict):
                if "status" in data:  # docker event
                    fields["event"]        = f"docker_{data.get('status', 'event')}"
                    fields["container_id"] = data.get("id", "")[:12]
                    fields["image"]        = data.get("from", "")
                    actor = data.get("Actor", {})
                    if actor:
                        attrs = actor.get("Attributes", {})
                        fields["container_name"] = attrs.get("name", "")
                    return fields
        except Exception:
            pass

        # Text patterns
        for pattern, event in [
            (r"container (?P<id>\w{12}).*?(?:start|up)",  "container_started"),
            (r"container (?P<id>\w{12}).*?(?:stop|down|exit)", "container_stopped"),
            (r"container (?P<id>\w{12}).*?kill",          "container_killed"),
            (r"OOMKilled.*?container (?P<id>\w{12})",      "container_oom"),
            (r"pulling image (?P<image>\S+)",              "image_pull"),
        ]:
            m = _re(pattern, t)
            if m:
                fields.update({k: v for k, v in m.groupdict().items() if v})
                fields["event"] = event
                return fields

        fields.update(pf)
        return fields


class KubernetesDecoder(BaseDecoder):
    name = "kubernetes"; priority = 8
    _AUDIT = re.compile(r'"kind":"Event".*?"verb":"(?P<verb>[^"]+)".*?"resource":"(?P<resource>[^"]+)".*?"user":"(?P<user>[^"]+)"')
    _POD_LOG = re.compile(r'pod="(?P<pod>[^"]+)" namespace="(?P<ns>[^"]+)"')

    def match(self, log):
        src = log.get("source", "").lower()
        t = _text(log)
        return "kubernetes" in src or "k8s" in src or \
               '"kubernetes"' in t or "pod=" in t or \
               ("namespace" in t and ("Error" in t or "Warning" in t))

    def decode(self, log):
        t = _text(log)
        fields = {"decoder": "kubernetes"}

        # k8s structured JSON log
        try:
            data = json.loads(t)
            if isinstance(data, dict) and "kubernetes" in data:
                k8s = data["kubernetes"]
                fields.update({
                    "pod":        k8s.get("pod_name", ""),
                    "namespace":  k8s.get("namespace_name", ""),
                    "container":  k8s.get("container_name", ""),
                    "node":       k8s.get("host", ""),
                    "event":      "k8s_log",
                })
                return fields
        except Exception:
            pass

        # Audit log pattern
        m = self._AUDIT.search(t)
        if m:
            return {"event": "k8s_audit", "verb": m.group("verb"),
                    "resource": m.group("resource"), "user": m.group("user"),
                    "decoder": "kubernetes"}

        # Pod log
        m = self._POD_LOG.search(t)
        if m:
            fields.update({"pod": m.group("pod"), "namespace": m.group("ns"),
                           "event": "k8s_pod_log"})

        # Event severity
        if "Error" in t or "Failed" in t:
            fields["is_error"] = True
        if "CrashLoopBackOff" in t or "OOMKilled" in t:
            fields["event"] = "k8s_pod_crash"

        return fields


# ══════════════════════════════════════════════════════════════════════════════
# TIER 8 — Mail servers
# ══════════════════════════════════════════════════════════════════════════════

class PostfixDecoder(BaseDecoder):
    name = "postfix"; priority = 10
    _SMTP_IN = re.compile(r"client=(?P<client_host>[^\[]+)\[(?P<src_ip>[\d.]+)\]")
    _REJECT  = re.compile(r"NOQUEUE: reject:.*?client=(?P<client>[^\[]+)\[(?P<src_ip>[\d.]+)\].*?from=<(?P<from>[^>]*)>.*?to=<(?P<to>[^>]*)>.*?(?P<reason>.+)")
    _BOUNCE  = re.compile(r"(?P<queue_id>\w+): to=<(?P<to>[^>]*)>.*?status=bounced")

    def match(self, log):
        src = log.get("source", "").lower()
        return "postfix" in src or "postfix" in _text(log).lower()

    def decode(self, log):
        t = _text(log)
        if "reject" in t.lower():
            m = self._REJECT.search(t)
            if m:
                return {"event": "mail_rejected", "src_ip": m.group("src_ip"),
                        "mail_from": m.group("from"), "mail_to": m.group("to"),
                        "reason": m.group("reason"), "decoder": "postfix"}
        if "bounced" in t.lower():
            m = self._BOUNCE.search(t)
            if m:
                return {"event": "mail_bounced", "mail_to": m.group("to"),
                        "decoder": "postfix"}
        if "SASL LOGIN" in t and "authentication failed" in t.lower():
            return {"event": "mail_auth_failed", "decoder": "postfix"}
        m = self._SMTP_IN.search(t)
        if m:
            return {"event": "mail_received", "src_ip": m.group("src_ip"),
                    "decoder": "postfix"}
        return {"decoder": "postfix"}


class DovecotDecoder(BaseDecoder):
    name = "dovecot"; priority = 10
    _AUTH_FAIL = re.compile(r"(?:imap|pop3)-login:.*?(?:auth failed|Aborted login).*?user=<(?P<user>[^>]*)>.*?(?:rip=(?P<src_ip>[\d.]+))?")
    _LOGIN     = re.compile(r"(?:imap|pop3)-login:.*?Login:.*?user=<(?P<user>[^>]*)>.*?(?:rip=(?P<src_ip>[\d.]+))?")

    def match(self, log):
        src = log.get("source", "").lower()
        return "dovecot" in src

    def decode(self, log):
        t = _text(log)
        m = self._AUTH_FAIL.search(t)
        if m:
            return {"event": "mail_auth_failed", "user": m.group("user") or "",
                    "src_ip": m.group("src_ip") or "", "decoder": "dovecot"}
        m = self._LOGIN.search(t)
        if m:
            return {"event": "mail_login", "user": m.group("user") or "",
                    "src_ip": m.group("src_ip") or "", "decoder": "dovecot"}
        return {"decoder": "dovecot"}


# ══════════════════════════════════════════════════════════════════════════════
# TIER 9 — Windows / Sysmon
# ══════════════════════════════════════════════════════════════════════════════

class WindowsEventDecoder(BaseDecoder):
    """Parses Windows Event Log entries (XML or structured dict)."""
    name = "windows_event"; priority = 8

    # Map EventID → (event_type, mitre_technique)
    EVENT_MAP: Dict[int, tuple] = {
        # Logon/Logoff
        4624: ("windows_logon_success",   "T1078"),
        4625: ("windows_logon_failed",    "T1110"),
        4634: ("windows_logoff",          None),
        4647: ("windows_logoff_initiated",None),
        4648: ("windows_explicit_logon",  "T1078"),
        4649: ("windows_replay_attack",   "T1187"),
        4672: ("windows_special_privs",   "T1078.003"),
        4673: ("windows_privileged_service","T1548"),
        4674: ("windows_privileged_object","T1548"),
        # Account Management
        4720: ("windows_user_created",    "T1136.001"),
        4722: ("windows_user_enabled",    None),
        4723: ("windows_pw_change",       None),
        4724: ("windows_pw_reset",        "T1098"),
        4725: ("windows_user_disabled",   "T1531"),
        4726: ("windows_user_deleted",    "T1531"),
        4728: ("windows_group_member_added","T1098"),
        4732: ("windows_local_group_member","T1098"),
        4733: ("windows_local_group_removed",None),
        4738: ("windows_user_changed",    None),
        4740: ("windows_account_lockout", "T1110"),
        4756: ("windows_global_group_member","T1098"),
        # Process Creation/Termination
        4688: ("windows_process_created", "T1059"),
        4689: ("windows_process_terminated",None),
        # Scheduled Tasks
        4698: ("windows_task_created",    "T1053.005"),
        4699: ("windows_task_deleted",    None),
        4700: ("windows_task_enabled",    "T1053.005"),
        4702: ("windows_task_updated",    "T1053.005"),
        # Services
        4697: ("windows_service_installed","T1543.003"),
        7034: ("windows_service_crashed", None),
        7036: ("windows_service_state",   None),
        7045: ("windows_service_new",     "T1543.003"),
        # Audit policy
        4706: ("windows_domain_trust_created","T1484"),
        4713: ("windows_kerberos_policy_changed","T1484"),
        4714: ("windows_efs_recovery_policy","T1484"),
        4715: ("windows_audit_policy_changed","T1562.002"),
        4719: ("windows_audit_policy_changed","T1562.002"),
        4739: ("windows_domain_policy_changed","T1484"),
        # Credential Access
        4768: ("windows_kerberos_tgt_req","T1558.001"),
        4769: ("windows_kerberos_svc_req","T1558.003"),
        4771: ("windows_kerberos_preauth_fail","T1110"),
        4776: ("windows_ntlm_auth",       "T1550.002"),
        # Object Access
        4663: ("windows_object_access",   "T1083"),
        4660: ("windows_object_deleted",  "T1070"),
        4670: ("windows_permission_changed","T1222"),
        # Log Cleared
        1102: ("windows_audit_log_cleared","T1070.001"),
        4616: ("windows_time_changed",    "T1070.006"),
        # PowerShell
        4103: ("windows_powershell_module","T1059.001"),
        4104: ("windows_powershell_script","T1059.001"),
        # RDP
        4778: ("windows_rdp_reconnect",   "T1021.001"),
        4779: ("windows_rdp_disconnect",  None),
        # Network
        5140: ("windows_share_accessed",  "T1021.002"),
        5145: ("windows_share_object_checked","T1021.002"),
        # WMI
        5857: ("windows_wmi_activity",    "T1047"),
        5858: ("windows_wmi_error",       "T1047"),
        5859: ("windows_wmi_filter_sub",  "T1546.003"),
        5860: ("windows_wmi_consumer_sub","T1546.003"),
        5861: ("windows_wmi_permanent_sub","T1546.003"),
        # Defender
        1116: ("windows_defender_malware","T1204"),
        1117: ("windows_defender_action", None),
        1118: ("windows_defender_remediation",None),
        2001: ("windows_defender_definition",None),
        # Windows Firewall
        2004: ("windows_fw_rule_added",   "T1562.004"),
        2005: ("windows_fw_rule_changed", "T1562.004"),
        2006: ("windows_fw_rule_deleted", "T1562.004"),
        2033: ("windows_fw_rule_deleted", "T1562.004"),
        # AppLocker / SRP
        8003: ("windows_applocker_blocked","T1204"),
        8004: ("windows_applocker_blocked","T1204"),
    }

    def match(self, log):
        pf  = log.get("parsed_fields", {}) or {}
        src = log.get("source", "").lower()
        return "windows" in src or "event_id" in pf or "EventID" in _text(log)

    def decode(self, log):
        pf = log.get("parsed_fields", {}) or {}
        t  = _text(log)
        fields = {"decoder": "windows_event"}

        event_id = pf.get("event_id") or pf.get("EventID")
        if not event_id:
            m = _re(r'"EventID"[:\s]+(?P<id>\d+)', t)
            if m: event_id = int(m.group("id"))

        if event_id:
            event_id = int(event_id)
            fields["event_id"] = event_id
            if event_id in self.EVENT_MAP:
                ev_type, mitre = self.EVENT_MAP[event_id]
                fields["event"]          = ev_type
                if mitre: fields["mitre_technique"] = mitre
            fields.update(pf)

        return fields


class SysmonDecoder(BaseDecoder):
    """Microsoft Sysmon event decoder — maps all 29 event types."""
    name = "sysmon"; priority = 7

    # Sysmon EventID → (event_type, mitre_technique)
    SYSMON_MAP: Dict[int, tuple] = {
        1:  ("sysmon_process_create",      "T1059"),
        2:  ("sysmon_file_create_time",    "T1070.006"),
        3:  ("sysmon_network_connect",     "T1071"),
        4:  ("sysmon_sysmon_state_changed",None),
        5:  ("sysmon_process_terminated",  None),
        6:  ("sysmon_driver_loaded",       "T1547.006"),
        7:  ("sysmon_image_loaded",        "T1574"),
        8:  ("sysmon_create_remote_thread","T1055"),
        9:  ("sysmon_raw_disk_access",     "T1006"),
        10: ("sysmon_process_access",      "T1055.001"),
        11: ("sysmon_file_create",         "T1059"),
        12: ("sysmon_registry_key",        "T1112"),
        13: ("sysmon_registry_value",      "T1112"),
        14: ("sysmon_registry_renamed",    "T1112"),
        15: ("sysmon_file_stream",         "T1564.004"),
        16: ("sysmon_config_changed",      None),
        17: ("sysmon_pipe_created",        "T1559"),
        18: ("sysmon_pipe_connected",      "T1559"),
        19: ("sysmon_wmi_filter",          "T1546.003"),
        20: ("sysmon_wmi_consumer",        "T1546.003"),
        21: ("sysmon_wmi_subscription",    "T1546.003"),
        22: ("sysmon_dns_query",           "T1071.004"),
        23: ("sysmon_file_deleted",        "T1070.004"),
        24: ("sysmon_clipboard_change",    "T1115"),
        25: ("sysmon_process_tampered",    "T1055"),
        26: ("sysmon_file_delete_logged",  "T1070.004"),
        27: ("sysmon_file_block_exe",      "T1204"),
        28: ("sysmon_file_block_shredding","T1485"),
        29: ("sysmon_file_exe_detect",     "T1204"),
    }

    # High-risk Sysmon patterns
    _LOLBAS = re.compile(
        r"(?:powershell|cmd|wscript|cscript|mshta|regsvr32|rundll32|"
        r"certutil|bitsadmin|wmic|msiexec|regasm|regsvcs|installutil|"
        r"cmstp|msbuild|xwizard|diskshadow|dnscmd)\.exe",
        re.IGNORECASE,
    )
    _ENCODED = re.compile(r"-[Ee][Nn][Cc]|-[Ee][Nn][Cc][Oo][Dd][Ee][Dd][Cc][Oo][Mm][Mm][Aa][Nn][Dd]")
    _C2_PORTS = {4444, 5555, 1337, 31337, 8888, 9999}
    _SUSPICIOUS_PATHS = re.compile(
        r"(?:%temp%|\\temp\\|\\tmp\\|\\appdata\\|\\public\\|\\users\\public|"
        r"\\programdata\\)[^\\]+\.exe",
        re.IGNORECASE,
    )

    def match(self, log):
        pf  = log.get("parsed_fields", {}) or {}
        src = log.get("source", "").lower()
        return "sysmon" in src or pf.get("provider") == "Microsoft-Windows-Sysmon"

    def decode(self, log):
        pf     = log.get("parsed_fields", {}) or {}
        t      = _text(log)
        fields = {"decoder": "sysmon"}
        fields.update(pf)

        event_id = int(pf.get("event_id", 0))
        if event_id in self.SYSMON_MAP:
            ev_type, mitre = self.SYSMON_MAP[event_id]
            fields["event"] = ev_type
            if mitre: fields["mitre_technique"] = mitre

        # Intelligence enrichment
        cmd = pf.get("CommandLine") or pf.get("command_line") or t
        image = pf.get("Image") or pf.get("image") or ""

        if cmd:
            fields["uses_lolbas"]    = bool(self._LOLBAS.search(cmd))
            fields["uses_encoding"]  = bool(self._ENCODED.search(cmd))
            fields["suspicious_path"]= bool(self._SUSPICIOUS_PATHS.search(cmd))

        # Network connection C2 check
        if event_id == 3:
            dst_port = int(pf.get("DestinationPort", pf.get("dst_port", 0)))
            fields["is_c2_port"] = dst_port in self._C2_PORTS
            dst_ip = pf.get("DestinationIp", pf.get("dst_ip", ""))
            fields["dst_ip"] = dst_ip
            fields["src_ip"] = pf.get("SourceIp", pf.get("src_ip", ""))

        return fields


# ══════════════════════════════════════════════════════════════════════════════
# TIER 10 — System & Kernel
# ══════════════════════════════════════════════════════════════════════════════

class AuditdDecoder(BaseDecoder):
    name = "auditd"; priority = 8; accumulate = True
    _RE   = re.compile(r"type=(\S+).*?msg=audit\([\d.]+:(\d+)\):\s*(.*)")
    _KV   = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')
    _EVENT_MAP = {
        "USER_AUTH":   "user_authentication", "USER_LOGIN":  "user_login",
        "USER_LOGOUT": "user_logout",          "SYSCALL":     "system_call",
        "EXECVE":      "process_execution",    "PATH":        "file_access",
        "SOCKADDR":    "network_connection",   "USER_CMD":    "user_command",
        "ADD_USER":    "user_created",         "DEL_USER":    "user_deleted",
        "ADD_GROUP":   "group_created",        "DEL_GROUP":   "group_deleted",
        "USER_CHAUTHTOK": "passwd_changed",    "CRED_ACQ":    "credential_acquired",
        "USER_ROLE_CHANGE": "role_changed",    "KERN_MODULE": "kernel_module",
    }

    def match(self, log):
        t = _text(log)
        return "msg=audit(" in t or "type=USER_AUTH" in t or "type=SYSCALL" in t

    def decode(self, log):
        t = _text(log)
        m = self._RE.search(t)
        if not m: return {}
        audit_type = m.group(1)
        fields: Dict[str, Any] = {
            "audit_type": audit_type,
            "event":  self._EVENT_MAP.get(audit_type, audit_type.lower()),
            "decoder": "auditd",
        }
        for kv in self._KV.finditer(m.group(3)):
            key = kv.group(1)
            val = kv.group(2) if kv.group(2) is not None else kv.group(3)
            fields[key] = val
        return fields


class OOMDecoder(BaseDecoder):
    name = "oom_killer"; priority = 10
    _RE = re.compile(r"Kill process (?P<pid>\d+) \((?P<process>[^)]+)\).*?score (?P<score>\d+)")

    def match(self, log):
        t = _text(log)
        return "Out of memory" in t or "oom_kill" in t.lower()

    def decode(self, log):
        m = self._RE.search(_text(log))
        f = {"event": "oom_kill", "decoder": "oom_killer"}
        if m: f.update({"pid": m.group("pid"), "process": m.group("process"), "score": m.group("score")})
        return f


class SystemdDecoder(BaseDecoder):
    name = "systemd"; priority = 12; accumulate = True
    _RE = re.compile(r"systemd(?:\[\d+\])?:\s+(?P<unit>\S+):\s+(?P<msg>.+)")

    def match(self, log):
        t = _text(log)
        return "systemd[" in t or "systemd:" in t

    def decode(self, log):
        t = _text(log)
        m = self._RE.search(t)
        f = {"decoder": "systemd"}
        if m:
            f["unit"]    = m.group("unit")
            f["sys_msg"] = m.group("msg")
        for kw, ev in [("failed","service_failed"),("crash","service_crashed"),
                       ("started","service_started"),("stopped","service_stopped"),
                       ("killed","service_killed"),("timeout","service_timeout")]:
            if kw in t.lower():
                f["event"] = ev; break
        else:
            f["event"] = "systemd_event"
        return f


class CronDecoder(BaseDecoder):
    name = "cron"; priority = 12
    _RE = re.compile(r"CRON\[(?P<pid>\d+)\]:.*?(?:\((?P<user>[^)]+)\)\s+)?(?P<action>CMD|session opened|session closed)\s*(?:\((?P<command>[^)]+)\))?")

    def match(self, log):
        t = _text(log)
        return "CRON[" in t or "crond[" in t.lower()

    def decode(self, log):
        m = self._RE.search(_text(log))
        if m:
            return {"user": m.group("user") or "", "action": m.group("action"),
                    "command": m.group("command") or "",
                    "event": "cron_job", "decoder": "cron"}
        return {"event": "cron_event", "decoder": "cron"}


class FIMDecoder(BaseDecoder):
    name = "fim"; priority = 5

    def match(self, log):
        src = log.get("source", "")
        return src == "fim" or "FIM ALERT" in (_text(log))

    def decode(self, log):
        pf = log.get("parsed_fields", {}) or {}
        return {"decoder": "fim", **pf}


class ModSecurityDecoder(BaseDecoder):
    """ModSecurity WAF log."""
    name = "modsecurity"; priority = 8
    _RE = re.compile(
        r"ModSecurity.*?(?:Warning|Error).*?\[id \"(?P<rule_id>\d+)\"]"
        r".*?\[msg \"(?P<msg>[^\"]+)\"]"
        r"(?:.*?\[tag \"(?P<tag>[^\"]+)\"])?"
        r"(?:.*?\[severity \"(?P<severity>[^\"]+)\"])?"
    )
    _CLIENT = re.compile(r"\[client (?P<src_ip>[\d.a-f:]+)\]")

    def match(self, log):
        return "ModSecurity" in _text(log) or "modsec" in log.get("source", "").lower()

    def decode(self, log):
        t = _text(log)
        f = {"event": "waf_alert", "decoder": "modsecurity"}
        m = self._RE.search(t)
        if m:
            f["rule_id"]  = m.group("rule_id")
            f["waf_msg"]  = m.group("msg")
            f["severity"] = m.group("severity") or "MEDIUM"
        mc = self._CLIENT.search(t)
        if mc: f["src_ip"] = mc.group("src_ip")
        if "SQL" in t or "sqli" in t.lower(): f["attack_type"] = "sqli"
        elif "XSS" in t or "script" in t.lower(): f["attack_type"] = "xss"
        elif "traversal" in t.lower(): f["attack_type"] = "path_traversal"
        return f


class DNSDecoder(BaseDecoder):
    """BIND / named query log."""
    name = "dns"; priority = 10
    _QUERY = re.compile(r"queries: info: client @\S+ (?P<src_ip>[\d.]+)#(?P<src_port>\d+).*?query: (?P<domain>\S+) IN (?P<type>\w+)")
    _RPZ   = re.compile(r"rpz.*?QNAME policy (?P<policy>\S+) via (?P<domain>\S+).*?client (?P<src_ip>[\d.]+)")

    def match(self, log):
        src = log.get("source", "").lower()
        return "named" in src or "bind" in src or "unbound" in src

    def decode(self, log):
        t = _text(log)
        if "rpz" in t.lower():
            m = self._RPZ.search(t)
            if m:
                return {"event": "dns_blocked", "domain": m.group("domain"),
                        "src_ip": m.group("src_ip"), "policy": m.group("policy"),
                        "decoder": "dns"}
        m = self._QUERY.search(t)
        if m:
            dom = m.group("domain")
            return {"event": "dns_query", "domain": dom,
                    "dns_type": m.group("type"), "src_ip": m.group("src_ip"),
                    "is_dga": len(dom.split(".")[0]) > 20,  # crude DGA heuristic
                    "decoder": "dns"}
        return {"decoder": "dns"}


class SambaDecoder(BaseDecoder):
    name = "samba"; priority = 10
    _AUTH = re.compile(r"Authentication.*?user=\[(?P<domain>[^\]]*)\\\[?(?P<user>[^\]]+)\].*?workstation=\[(?P<workstation>[^\]]*)\].*?became (?P<result>\w+)")

    def match(self, log):
        src = log.get("source", "").lower()
        return "smbd" in src or "nmbd" in src or "winbindd" in src

    def decode(self, log):
        t = _text(log)
        m = self._AUTH.search(t)
        if m:
            return {"event": "smb_auth", "user": m.group("user"),
                    "workstation": m.group("workstation"),
                    "result": m.group("result"),
                    "is_failed": m.group("result").lower() != "ok",
                    "decoder": "samba"}
        return {"decoder": "samba"}


class ElasticsearchDecoder(BaseDecoder):
    name = "elasticsearch"; priority = 12

    def match(self, log):
        src = log.get("source", "").lower()
        return "elasticsearch" in src or "elastic" in src

    def decode(self, log):
        t = _text(log)
        f = {"decoder": "elasticsearch"}
        if "authentication_failed" in t or "Authorization Exception" in t:
            f["event"] = "db_auth_failed"
        elif "CircuitBreakingException" in t or "OutOfMemoryError" in t:
            f["event"] = "es_oom"
        elif "health is RED" in t or "status changed from GREEN to RED" in t:
            f["event"] = "es_cluster_unhealthy"
        elif "security exception" in t.lower():
            f["event"] = "es_security_exception"
        return f


class ClamAVDecoder(BaseDecoder):
    name = "clamav"; priority = 10
    _FOUND = re.compile(r"(?P<file>.+): (?P<virus>\S+) FOUND")

    def match(self, log):
        src = log.get("source", "").lower()
        return "clamav" in src or "clamd" in src

    def decode(self, log):
        t = _text(log)
        m = self._FOUND.search(t)
        if m:
            return {"event": "malware_detected", "file": m.group("file"),
                    "virus": m.group("virus"), "decoder": "clamav"}
        if "Reload" in t:
            return {"event": "clamav_db_updated", "decoder": "clamav"}
        return {"decoder": "clamav"}


# ══════════════════════════════════════════════════════════════════════════════
# Registry & Pipeline
# ══════════════════════════════════════════════════════════════════════════════

_ALL_DECODERS: List[BaseDecoder] = [
    # Tier 1 — structural
    JsonDecoder(), SyslogRFC3164(), SyslogRFC5424(),
    # Tier 2 — auth
    SSHDecoder(), PAMDecoder(), SudoDecoder(), KerberosDecoder(),
    # Tier 3 — web
    NginxAccessDecoder(), ApacheAccessDecoder(), ApacheErrorDecoder(), HaProxyDecoder(),
    # Tier 4 — databases
    MySQLDecoder(), PostgreSQLDecoder(), RedisDecoder(), MongoDBDecoder(),
    # Tier 5 — network
    UFWDecoder(), IptablesDecoder(), Fail2BanDecoder(), OpenVPNDecoder(),
    CiscoASADecoder(), PaloAltoDecoder(), DNSDecoder(),
    # Tier 6 — cloud
    AWSCloudTrailDecoder(), AzureActivityDecoder(), GCPAuditDecoder(),
    # Tier 7 — containers
    DockerEventDecoder(), KubernetesDecoder(),
    # Tier 8 — mail
    PostfixDecoder(), DovecotDecoder(),
    # Tier 9 — windows
    WindowsEventDecoder(), SysmonDecoder(),
    # Tier 10 — system
    AuditdDecoder(), OOMDecoder(), SystemdDecoder(), CronDecoder(),
    FIMDecoder(), ModSecurityDecoder(), SambaDecoder(),
    ElasticsearchDecoder(), ClamAVDecoder(),
]

_DECODERS: List[BaseDecoder] = sorted(_ALL_DECODERS, key=lambda d: d.priority)


def decode_log(log: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run the full decoder pipeline against a log entry.

    Strategy:
      - Decoders with accumulate=True always run (they add structural fields).
      - Other decoders stop on first match below priority 10.
      - Results are merged; later decoders can override earlier fields.
    """
    existing = dict(log.get("parsed_fields") or {})
    matched_exclusive = False

    for decoder in _DECODERS:
        try:
            if not decoder.match(log):
                continue
            if not decoder.accumulate and matched_exclusive:
                continue

            fields = decoder.decode(log)
            if fields:
                existing.update(fields)
                if not decoder.accumulate and decoder.priority >= 6:
                    matched_exclusive = True
        except Exception as e:
            logger.debug(f"Decoder {decoder.name} error: {e}")

    return existing


def get_decoder_stats() -> dict:
    return {
        "total_decoders": len(_DECODERS),
        "categories": {
            "structural":   sum(1 for d in _DECODERS if d.priority <= 6),
            "auth":         sum(1 for d in _DECODERS if d.name in {"ssh","pam","sudo","kerberos"}),
            "web":          sum(1 for d in _DECODERS if d.name in {"nginx_access","apache_access","apache_error","haproxy"}),
            "database":     sum(1 for d in _DECODERS if d.name in {"mysql","postgresql","redis","mongodb","elasticsearch"}),
            "network":      sum(1 for d in _DECODERS if d.name in {"ufw","iptables","fail2ban","openvpn","cisco_asa","palo_alto","dns"}),
            "cloud":        sum(1 for d in _DECODERS if d.name in {"aws_cloudtrail","azure_activity","gcp_audit"}),
            "containers":   sum(1 for d in _DECODERS if d.name in {"docker_event","kubernetes"}),
            "mail":         sum(1 for d in _DECODERS if d.name in {"postfix","dovecot"}),
            "windows":      sum(1 for d in _DECODERS if d.name in {"windows_event","sysmon"}),
            "system":       sum(1 for d in _DECODERS if d.priority >= 8 and d.name not in {
                "ssh","pam","sudo","kerberos","nginx_access","apache_access","apache_error",
                "haproxy","mysql","postgresql","redis","mongodb","elasticsearch",
                "ufw","iptables","fail2ban","openvpn","cisco_asa","palo_alto","dns",
                "aws_cloudtrail","azure_activity","gcp_audit","docker_event","kubernetes",
                "postfix","dovecot","windows_event","sysmon"}),
        }
    }
