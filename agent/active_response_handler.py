"""
Active Response handler for the SecureWatch SIEM agent.

Executes actions received from the server:
  block_ip / unblock_ip — firewall rule via iptables, nftables, ufw, or netsh
  kill_process          — SIGKILL by PID or process name
  disable_user          — lock account (usermod -L / net user /active:no)
  enable_user           — unlock account (usermod -U / net user /active:yes)
  run_script            — execute a pre-approved script with strict path validation

Security invariants:
  - All user-supplied strings are validated before being passed to the shell.
  - IP addresses are parsed with the `ipaddress` stdlib; invalid values abort immediately.
  - Usernames and process names are restricted to a safe character allowlist.
  - run_script accepts only absolute paths with no shell metacharacters.
  - Private/loopback IPs are blocked at the engine level, but the handler
    refuses them too as a defence-in-depth measure.
  - Commands run with a hard timeout (default 30 s).
"""
import ipaddress
import logging
import os
import platform
import re
import shlex
import subprocess
from typing import Dict, Any, Callable, Optional, Tuple

logger = logging.getLogger("siem-agent.ar")

_SYSTEM   = platform.system()
_IS_LINUX = _SYSTEM == "Linux"
_IS_WIN   = _SYSTEM == "Windows"
_IS_MAC   = _SYSTEM == "Darwin"

# Populated once at module load — avoids repeated `which` lookups
_UFW_BIN:      Optional[str] = None
_NFTABLES_BIN: Optional[str] = None
_IPTABLES_BIN: Optional[str] = None
_PFCTL_BIN:    Optional[str] = None   # macOS

if _IS_LINUX:
    import shutil
    _UFW_BIN      = shutil.which("ufw")
    _NFTABLES_BIN = shutil.which("nft")
    _IPTABLES_BIN = shutil.which("iptables")

if _IS_MAC:
    import shutil
    _PFCTL_BIN = shutil.which("pfctl")

# ── Private network guard ─────────────────────────────────────────────────────

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


# ── Input validation ──────────────────────────────────────────────────────────

# Allowed: alphanumeric, hyphen, underscore, dot — covers almost all real usernames
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")
# Allowed: alphanumeric, hyphen, underscore, dot, slash (for paths like /usr/bin/python3)
_PROCNAME_RE = re.compile(r"^[a-zA-Z0-9._/+-]{1,256}$")
# Script must be an absolute path, no shell meta-characters
# Unix: /path/to/script  Windows: C:\path\script.bat or C:/path/script.bat
_SCRIPT_RE_UNIX = re.compile(r"^/[a-zA-Z0-9._/+-]{1,512}$")
_SCRIPT_RE_WIN  = re.compile(r"^[A-Za-z]:[/\\][a-zA-Z0-9._/\\+-]{1,511}$")


def _validate_ip(ip: str) -> Tuple[bool, str]:
    if not ip:
        return False, "IP address is empty"
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False, f"Invalid IP address: {ip!r}"
    if _is_private(ip):
        return False, f"Refusing to block private/loopback address {ip}"
    return True, ""


def _validate_username(user: str) -> Tuple[bool, str]:
    if not user:
        return False, "Username is empty"
    if not _USERNAME_RE.match(user):
        return False, f"Username contains disallowed characters: {user!r}"
    return True, ""


def _validate_process_name(name: str) -> Tuple[bool, str]:
    if not name:
        return False, "Process name is empty"
    if not _PROCNAME_RE.match(name):
        return False, f"Process name contains disallowed characters: {name!r}"
    return True, ""


def _validate_script_path(path: str) -> Tuple[bool, str]:
    if not path:
        return False, "Script path is empty"
    if not os.path.isabs(path):
        return False, "Script must be an absolute path"
    re_ok = _SCRIPT_RE_WIN.match(path) if _IS_WIN else _SCRIPT_RE_UNIX.match(path)
    if not re_ok:
        return False, f"Script path contains disallowed characters: {path!r}"
    if not os.path.isfile(path):
        return False, f"Script not found on disk: {path!r}"
    if not _IS_WIN and not os.access(path, os.X_OK):
        return False, f"Script is not executable: {path!r}"
    return True, ""


# ── Shell runner ──────────────────────────────────────────────────────────────

def _run(args: list, timeout: int = 30) -> Tuple[bool, str]:
    """Run a command expressed as a list of strings (never a raw shell string)."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,     # explicit: never use shell=True with user data
        )
        output = (result.stdout + result.stderr).strip()
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, f"Command timed out after {timeout}s"
    except FileNotFoundError:
        return False, f"Executable not found: {args[0]!r}"
    except Exception as exc:
        return False, str(exc)


# ── Action implementations ────────────────────────────────────────────────────

def _block_ip(params: Dict[str, Any]) -> Tuple[bool, str]:
    ip = (params.get("src_ip") or params.get("ip") or "").strip()
    ok, msg = _validate_ip(ip)
    if not ok:
        return False, msg

    if _IS_LINUX:
        return _linux_firewall_block(ip, block=True)
    if _IS_WIN:
        return _windows_firewall_block(ip, block=True)
    if _IS_MAC:
        return _macos_firewall_block(ip, block=True)
    return False, f"Unsupported OS: {_SYSTEM}"


def _unblock_ip(params: Dict[str, Any]) -> Tuple[bool, str]:
    ip = (params.get("src_ip") or params.get("ip") or "").strip()
    try:
        ipaddress.ip_address(ip)   # validate format; allow private for unblock
    except ValueError:
        return False, f"Invalid IP address: {ip!r}"
    if not ip:
        return False, "No IP address provided"

    if _IS_LINUX:
        return _linux_firewall_block(ip, block=False)
    if _IS_WIN:
        return _windows_firewall_block(ip, block=False)
    if _IS_MAC:
        return _macos_firewall_block(ip, block=False)
    return False, f"Unsupported OS: {_SYSTEM}"


# ── Linux firewall ────────────────────────────────────────────────────────────

def _linux_firewall_block(ip: str, block: bool) -> Tuple[bool, str]:
    verb = "block" if block else "unblock"
    if _UFW_BIN:
        return _ufw_op(ip, block)
    if _NFTABLES_BIN:
        return _nft_op(ip, block)
    if _IPTABLES_BIN:
        return _iptables_op(ip, block)
    return False, f"No supported firewall found (tried ufw, nft, iptables) — cannot {verb} {ip}"


def _ufw_op(ip: str, block: bool) -> Tuple[bool, str]:
    if block:
        ok, out = _run([_UFW_BIN, "deny", "from", ip, "to", "any"])
    else:
        ok, out = _run([_UFW_BIN, "delete", "deny", "from", ip, "to", "any"])
    verb = "Blocked" if block else "Unblocked"
    return ok, f"{verb} {ip} via ufw: {out}"


def _nft_op(ip: str, block: bool) -> Tuple[bool, str]:
    # Uses a dedicated SIEM blacklist set; table/set must be pre-created by setup
    set_name = "siem_blocklist"
    if block:
        ok, out = _run([_NFTABLES_BIN, "add", "element", "inet", "filter", set_name, f"{{ {ip} }}"])
    else:
        ok, out = _run([_NFTABLES_BIN, "delete", "element", "inet", "filter", set_name, f"{{ {ip} }}"])
    verb = "Blocked" if block else "Unblocked"
    return ok, f"{verb} {ip} via nftables: {out}"


def _iptables_op(ip: str, block: bool) -> Tuple[bool, str]:
    flag = "-I" if block else "-D"
    ok, out = _run([_IPTABLES_BIN, flag, "INPUT", "-s", ip, "-j", "DROP"])
    verb = "Blocked" if block else "Unblocked"
    return ok, f"{verb} {ip} via iptables: {out}"


# ── Windows firewall ──────────────────────────────────────────────────────────

_NETSH = "netsh"

def _windows_firewall_block(ip: str, block: bool) -> Tuple[bool, str]:
    rule_name = f"SIEM_BLOCK_{ip}"
    if block:
        ok, out = _run([
            _NETSH, "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}",
        ])
    else:
        ok, out = _run([
            _NETSH, "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}",
        ])
    verb = "Blocked" if block else "Unblocked"
    return ok, f"{verb} {ip} via netsh: {out}"


# ── macOS firewall ────────────────────────────────────────────────────────────

def _macos_firewall_block(ip: str, block: bool) -> Tuple[bool, str]:
    if not _PFCTL_BIN:
        return False, "pfctl not found — cannot manage firewall on macOS"
    table = "siem_blocklist"
    if block:
        ok, out = _run([_PFCTL_BIN, "-t", table, "-T", "add", ip])
    else:
        ok, out = _run([_PFCTL_BIN, "-t", table, "-T", "delete", ip])
    verb = "Blocked" if block else "Unblocked"
    return ok, f"{verb} {ip} via pfctl: {out}"


# ── Process kill ──────────────────────────────────────────────────────────────

def _kill_process(params: Dict[str, Any]) -> Tuple[bool, str]:
    pid          = params.get("pid")
    process_name = (params.get("process_name") or params.get("process") or "").strip()

    if pid:
        try:
            pid_int = int(pid)
            if pid_int <= 1:
                return False, f"Refusing to kill PID {pid_int} (system process)"
        except (ValueError, TypeError):
            return False, f"Invalid PID value: {pid!r}"

        if _IS_LINUX or _IS_MAC:
            ok, out = _run(["kill", "-9", str(pid_int)])
        else:
            ok, out = _run(["taskkill", "/F", "/PID", str(pid_int)])
        return ok, f"Killed PID {pid_int}: {out}"

    if process_name:
        valid, msg = _validate_process_name(process_name)
        if not valid:
            return False, msg

        if _IS_LINUX or _IS_MAC:
            # pkill -x for exact name match — safer than -f (substring match)
            ok, out = _run(["pkill", "-9", "-x", process_name])
        else:
            ok, out = _run(["taskkill", "/F", "/IM", process_name])
        return ok, f"Killed process '{process_name}': {out}"

    return False, "Neither process_name nor pid provided"


# ── User management ───────────────────────────────────────────────────────────

def _disable_user(params: Dict[str, Any]) -> Tuple[bool, str]:
    user = (params.get("user") or params.get("username") or "").strip()
    ok, msg = _validate_username(user)
    if not ok:
        return False, msg

    if _IS_LINUX or _IS_MAC:
        ok, out = _run(["usermod", "-L", user])
        return ok, f"Locked user '{user}': {out}"
    if _IS_WIN:
        ok, out = _run(["net", "user", user, "/active:no"])
        return ok, f"Disabled user '{user}': {out}"
    return False, f"Unsupported OS: {_SYSTEM}"


def _enable_user(params: Dict[str, Any]) -> Tuple[bool, str]:
    user = (params.get("user") or params.get("username") or "").strip()
    ok, msg = _validate_username(user)
    if not ok:
        return False, msg

    if _IS_LINUX or _IS_MAC:
        ok, out = _run(["usermod", "-U", user])
        return ok, f"Unlocked user '{user}': {out}"
    if _IS_WIN:
        ok, out = _run(["net", "user", user, "/active:yes"])
        return ok, f"Enabled user '{user}': {out}"
    return False, f"Unsupported OS: {_SYSTEM}"


# ── Script execution ──────────────────────────────────────────────────────────

def _run_script(params: Dict[str, Any]) -> Tuple[bool, str]:
    """Execute a pre-approved script by absolute path only.

    Security model:
      - The script path must be absolute and match a strict character allowlist.
      - The script must exist on disk and be executable.
      - Arguments (if provided) are passed as a list — never shell-concatenated.
      - A configurable timeout caps runaway scripts.
    """
    script  = (params.get("script") or params.get("command") or "").strip()
    timeout = max(5, min(int(params.get("timeout", 60)), 300))

    valid, msg = _validate_script_path(script)
    if not valid:
        return False, msg

    # Optional positional arguments — each individually validated
    raw_args = params.get("args", [])
    if isinstance(raw_args, str):
        raw_args = shlex.split(raw_args)
    args = []
    for arg in raw_args:
        # Args must not contain shell expansion characters
        if re.search(r'[`$|;&<>{}()\\\n\r]', str(arg)):
            return False, f"Argument contains disallowed characters: {arg!r}"
        args.append(str(arg))

    ok, out = _run([script] + args, timeout=timeout)
    return ok, out


# ── Dispatch table ────────────────────────────────────────────────────────────

_HANDLERS: Dict[str, Callable[[Dict[str, Any]], Tuple[bool, str]]] = {
    "block_ip":     _block_ip,
    "unblock_ip":   _unblock_ip,
    "kill_process": _kill_process,
    "disable_user": _disable_user,
    "enable_user":  _enable_user,
    "run_script":   _run_script,
}


def execute_action(action: str, params: Dict[str, Any]) -> Tuple[bool, str]:
    handler = _HANDLERS.get(action)
    if not handler:
        logger.warning("AR: unknown action '%s' — skipping", action)
        return False, f"Unknown action: {action}"

    logger.info("AR: executing action=%s params_keys=%s", action, list(params.keys()))
    try:
        ok, result = handler(params)
        if ok:
            logger.info("AR: success action=%s result=%.200s", action, result)
        else:
            logger.error("AR: failed  action=%s result=%.200s", action, result)
        return ok, result
    except Exception as exc:
        logger.error("AR: exception action=%s: %s", action, exc, exc_info=True)
        return False, str(exc)
