"""
Active Response handler for the SecureWatch SIEM agent.
Executes actions received from the server (block_ip, kill_process, disable_user, run_script).
All actions are logged; failures are reported back to the server.
"""
import os
import sys
import logging
import subprocess
import platform
import shlex
from typing import Dict, Any

logger = logging.getLogger("siem-agent.ar")

_IS_LINUX   = platform.system() == "Linux"
_IS_WINDOWS = platform.system() == "Windows"


def _run(cmd: str, timeout: int = 30) -> tuple[bool, str]:
    """Run a shell command. Returns (success, output)."""
    try:
        result = subprocess.run(
            shlex.split(cmd) if _IS_LINUX else cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=_IS_WINDOWS,
        )
        output = (result.stdout + result.stderr).strip()
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, f"Command timed out after {timeout}s"
    except Exception as e:
        return False, str(e)


# ── Action implementations ────────────────────────────────────────────────────

def _block_ip(params: Dict[str, Any]) -> tuple[bool, str]:
    ip = params.get("src_ip") or params.get("ip")
    if not ip:
        return False, "No IP address provided"

    if _IS_LINUX:
        # Try ufw first, fall back to iptables
        ok, out = _run(f"which ufw")
        if ok:
            ok, out = _run(f"ufw deny from {ip} to any")
        else:
            ok, out = _run(f"iptables -I INPUT -s {ip} -j DROP")
        return ok, f"Blocked {ip}: {out}"

    if _IS_WINDOWS:
        ok, out = _run(
            f'netsh advfirewall firewall add rule name="SIEM_BLOCK_{ip}" '
            f'dir=in action=block remoteip={ip}'
        )
        return ok, f"Blocked {ip}: {out}"

    return False, f"Unsupported OS: {platform.system()}"


def _unblock_ip(params: Dict[str, Any]) -> tuple[bool, str]:
    ip = params.get("src_ip") or params.get("ip")
    if not ip:
        return False, "No IP address provided"

    if _IS_LINUX:
        ok, out = _run(f"which ufw")
        if ok:
            ok, out = _run(f"ufw delete deny from {ip} to any")
        else:
            ok, out = _run(f"iptables -D INPUT -s {ip} -j DROP")
        return ok, f"Unblocked {ip}: {out}"

    if _IS_WINDOWS:
        ok, out = _run(
            f'netsh advfirewall firewall delete rule name="SIEM_BLOCK_{ip}"'
        )
        return ok, f"Unblocked {ip}: {out}"

    return False, f"Unsupported OS: {platform.system()}"


def _kill_process(params: Dict[str, Any]) -> tuple[bool, str]:
    process_name = params.get("process_name") or params.get("process")
    pid          = params.get("pid")

    if pid:
        if _IS_LINUX:
            ok, out = _run(f"kill -9 {pid}")
        else:
            ok, out = _run(f"taskkill /F /PID {pid}")
        return ok, f"Killed PID {pid}: {out}"

    if process_name:
        if _IS_LINUX:
            ok, out = _run(f"pkill -9 -f {shlex.quote(process_name)}")
        else:
            ok, out = _run(f"taskkill /F /IM {process_name}")
        return ok, f"Killed process '{process_name}': {out}"

    return False, "No process name or PID provided"


def _disable_user(params: Dict[str, Any]) -> tuple[bool, str]:
    user = params.get("user") or params.get("username")
    if not user:
        return False, "No username provided"

    if _IS_LINUX:
        ok, out = _run(f"usermod -L {user}")
        return ok, f"Locked user '{user}': {out}"

    if _IS_WINDOWS:
        ok, out = _run(f"net user {user} /active:no")
        return ok, f"Disabled user '{user}': {out}"

    return False, f"Unsupported OS: {platform.system()}"


def _enable_user(params: Dict[str, Any]) -> tuple[bool, str]:
    user = params.get("user") or params.get("username")
    if not user:
        return False, "No username provided"

    if _IS_LINUX:
        ok, out = _run(f"usermod -U {user}")
        return ok, f"Unlocked user '{user}': {out}"

    if _IS_WINDOWS:
        ok, out = _run(f"net user {user} /active:yes")
        return ok, f"Enabled user '{user}': {out}"

    return False, f"Unsupported OS: {platform.system()}"


def _run_script(params: Dict[str, Any]) -> tuple[bool, str]:
    script  = params.get("script") or params.get("command")
    timeout = int(params.get("timeout", 60))

    if not script:
        return False, "No script/command provided"

    # Refuse obviously dangerous patterns
    _DANGEROUS = ("|", ";", "&&", "||", ">", "<", "`", "$(", "rm -rf", "mkfs", "dd if")
    for pattern in _DANGEROUS:
        if pattern in script and not params.get("allow_dangerous"):
            return False, f"Refused: script contains dangerous pattern '{pattern}'"

    ok, out = _run(script, timeout=timeout)
    return ok, out


# ── Dispatch ──────────────────────────────────────────────────────────────────

_HANDLERS = {
    "block_ip":     _block_ip,
    "unblock_ip":   _unblock_ip,
    "kill_process": _kill_process,
    "disable_user": _disable_user,
    "enable_user":  _enable_user,
    "run_script":   _run_script,
}


def execute_action(action: str, params: Dict[str, Any]) -> tuple[bool, str]:
    handler = _HANDLERS.get(action)
    if not handler:
        logger.warning(f"AR: Unknown action '{action}' — skipping")
        return False, f"Unknown action: {action}"

    logger.info(f"AR: Executing action={action} params={params}")
    try:
        ok, result = handler(params)
        level = logging.INFO if ok else logging.ERROR
        logger.log(level, f"AR: action={action} success={ok} result={result[:200]}")
        return ok, result
    except Exception as e:
        logger.error(f"AR: action={action} exception: {e}", exc_info=True)
        return False, str(e)
