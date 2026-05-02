"""
Windows Service Monitor — detects new service installations,
binary-path changes, start-type changes, and suspicious service configs.
Uses psutil on Windows; gracefully skips on non-Windows.
"""
import sys
import os
import re
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

IS_WINDOWS = sys.platform == "win32"
logger = logging.getLogger(__name__)

from collectors._paths import data_path as _data_path
_STATE_FILE = _data_path('.win_svc_state.json')

_MITRE = {
    "new_service":          "T1543.003",   # Create or Modify System Process: Windows Service
    "service_modified":     "T1543.003",
    "suspicious_service":   "T1543.003",
    "service_disabled":     "T1562.001",   # Impair Defenses
}

# Suspicious patterns in service binary paths
_SUSP_PATH = re.compile(
    r'(\\temp\\|\\tmp\\|\\appdata\\roaming\\|\\appdata\\local\\temp\\'
    r'|\\users\\public\\|\\programdata\\[^\\]+\\.exe'
    r'|cmd\.exe.*\/[Cc]'
    r'|powershell.*-[Ee]ncodedCommand|-[Ee]nc\s+[A-Za-z0-9+/=]{20}'
    r'|mshta\.exe|wscript\.exe|cscript\.exe'
    r'|regsvr32.*http|rundll32.*javascript)',
    re.IGNORECASE,
)

# Well-known critical services that should never be stopped/disabled
_CRITICAL_SERVICES = frozenset({
    "WinDefend", "MpsSvc", "EventLog", "wuauserv",
    "TermService", "LanmanServer", "LanmanWorkstation",
    "RpcSs", "DcomLaunch", "CryptSvc",
})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_services() -> Dict[str, Dict[str, Any]]:
    """Return {name: {binpath, status, start_type}} for all services."""
    if not IS_WINDOWS:
        return {}
    try:
        import psutil
        if not hasattr(psutil, 'win_service_iter'):
            logger.debug("Service monitor: psutil.win_service_iter unavailable (psutil too old)")
            return {}
        result = {}
        for svc in psutil.win_service_iter():
            try:
                info = svc.as_dict()
                result[info["name"]] = {
                    "display_name": info.get("display_name", ""),
                    "binpath":      info.get("binpath", ""),
                    "status":       info.get("status", ""),
                    "start_type":   info.get("start_type", ""),
                    "username":     info.get("username", ""),
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return result
    except Exception as e:
        logger.debug(f"Service enum error: {e}")
        return {}


def _load_state() -> Dict[str, Dict[str, Any]]:
    try:
        if os.path.exists(_STATE_FILE):
            with open(_STATE_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_state(state: Dict[str, Dict[str, Any]]):
    try:
        with open(_STATE_FILE, 'w') as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        logger.warning(f"Service monitor state save failed: {e}")


def _make_alert(
    level: str, event_type: str, svc_name: str,
    detail: str, mitre: str, extra: dict = None,
) -> Dict[str, Any]:
    msg = f"WIN-SVC [{event_type.upper()}] {svc_name}: {detail}"
    logger.warning(msg)
    fields: Dict[str, Any] = {
        "event_type":      event_type,
        "service_name":    svc_name,
        "mitre_technique": mitre,
        "detail":          detail,
    }
    if extra:
        fields.update(extra)
    return {
        "timestamp":     _now(),
        "level":         level,
        "source":        "windows_service_monitor",
        "message":       msg,
        "raw":           msg,
        "parsed_fields": fields,
    }


# ── Public API ────────────────────────────────────────────────────────────────

def initialize_service_baseline():
    """Snapshot all services at agent start."""
    if not IS_WINDOWS:
        return
    state = _get_services()
    _save_state(state)
    logger.info(f"Service monitor: baseline for {len(state)} services")


def check_services() -> List[Dict[str, Any]]:
    """Compare current services against baseline. Returns alerts."""
    if not IS_WINDOWS:
        return []

    alerts: List[Dict[str, Any]] = []
    old = _load_state()
    if not old:
        initialize_service_baseline()
        return []

    current = _get_services()
    changed = False

    # ── New services ──────────────────────────────────────────────────────────
    for name, info in current.items():
        if name not in old:
            detail = f"binpath={info['binpath'][:200]} start={info['start_type']}"
            level  = "CRITICAL" if _SUSP_PATH.search(info["binpath"]) else "HIGH"
            a = _make_alert(level, "new_service", name, detail, _MITRE["new_service"], {
                "binpath":    info["binpath"],
                "start_type": info["start_type"],
                "username":   info["username"],
                "suspicious_path": bool(_SUSP_PATH.search(info["binpath"])),
            })
            alerts.append(a)
            old[name] = info
            changed = True

    # ── Changed services ──────────────────────────────────────────────────────
    for name, info in current.items():
        if name not in old:
            continue
        prev = old[name]

        # Binary path change
        if info["binpath"] != prev.get("binpath", ""):
            alerts.append(_make_alert(
                "CRITICAL", "service_modified", name,
                f"binpath changed: {prev.get('binpath','')[:100]} → {info['binpath'][:100]}",
                _MITRE["service_modified"],
                {
                    "old_binpath": prev.get("binpath", ""),
                    "new_binpath": info["binpath"],
                    "change":      "binpath",
                },
            ))
            old[name]["binpath"] = info["binpath"]
            changed = True

        # Start type changed to disabled for critical services
        if (info["start_type"] == "disabled"
                and prev.get("start_type") != "disabled"
                and name in _CRITICAL_SERVICES):
            alerts.append(_make_alert(
                "HIGH", "service_disabled", name,
                f"Critical service disabled (was {prev.get('start_type','')})",
                _MITRE["service_disabled"],
                {"old_start_type": prev.get("start_type", ""), "service_name": name},
            ))
            old[name]["start_type"] = info["start_type"]
            changed = True

        # Suspicious path added to existing service
        if (not _SUSP_PATH.search(prev.get("binpath", ""))
                and _SUSP_PATH.search(info["binpath"])):
            alerts.append(_make_alert(
                "CRITICAL", "suspicious_service", name,
                f"Suspicious binary path: {info['binpath'][:200]}",
                _MITRE["suspicious_service"],
                {"binpath": info["binpath"]},
            ))
            changed = True

    if changed:
        _save_state(old)

    return alerts
