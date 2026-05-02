"""
Windows Registry FIM — monitors critical registry keys for persistence,
credential-access, and defense-evasion changes.
Uses winreg (stdlib), persists baseline to JSON. Only active on Windows.
"""
import sys
import os
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

IS_WINDOWS = sys.platform == "win32"
logger = logging.getLogger(__name__)

from collectors._paths import data_path as _data_path
_STATE_FILE = _data_path('.reg_fim_state.json')

# (hive_abbrev, subkey, mitre_technique, label)
_WATCH_KEYS: List[Tuple[str, str, str, str]] = [
    # ── Persistence: Run Keys ────────────────────────────────────────────────
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",             "T1547.001", "HKLM\\Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",         "T1547.001", "HKLM\\RunOnce"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",             "T1547.001", "HKCU\\Run"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",         "T1547.001", "HKCU\\RunOnce"),
    # Wow6432 (32-bit apps on 64-bit OS)
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "T1547.001", "HKLM\\Run(WOW)"),
    # ── Winlogon DLL hijack ───────────────────────────────────────────────────
    ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",     "T1547.004", "Winlogon"),
    # ── Image File Execution Options (IFEO Debugger) ─────────────────────────
    ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                                                                            "T1546.012", "IFEO"),
    # ── Services ─────────────────────────────────────────────────────────────
    ("HKLM", r"SYSTEM\CurrentControlSet\Services",                         "T1543.003", "Services"),
    # ── LSA / WDigest (credential dumping) ───────────────────────────────────
    ("HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa",                      "T1547.005", "LSA"),
    ("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDIGEST","T1112",     "WDigest"),
    # ── Boot Execute ─────────────────────────────────────────────────────────
    ("HKLM", r"SYSTEM\CurrentControlSet\Control\Session Manager",          "T1547.006", "BootExecute"),
    # ── AppInit DLLs ─────────────────────────────────────────────────────────
    ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",      "T1546.010", "AppInitDLLs"),
    # ── UAC policies (bypass) ────────────────────────────────────────────────
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "T1548.002", "UACPolicy"),
    # ── PowerShell execution policy ──────────────────────────────────────────
    ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\PowerShell",            "T1059.001", "PSPolicy"),
    # ── Windows Defender disable ──────────────────────────────────────────────
    ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows Defender",              "T1562.001", "DefenderPolicy"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",  "T1562.001", "DefenderRT"),
    # ── RDP enabled ──────────────────────────────────────────────────────────
    ("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server",          "T1021.001", "RDP"),
    # ── WinRM (lateral movement) ──────────────────────────────────────────────
    ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service",         "T1021.006", "WinRM"),
    # ── SilentProcessExit (persistence via WerFault) ─────────────────────────
    ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
                                                                            "T1546.012", "SilentExit"),
    # ── COM user hijack ───────────────────────────────────────────────────────
    ("HKCU", r"SOFTWARE\Classes\CLSID",                                    "T1546.015", "COMHijack"),
]


def _hive(name: str):
    import winreg
    return {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKU":  winreg.HKEY_USERS,
    }[name]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_key(hive_name: str, subkey: str) -> Dict[str, Any]:
    """Read all values under a registry key. Returns empty dict on error."""
    if not IS_WINDOWS:
        return {}
    try:
        import winreg
        result: Dict[str, Any] = {}
        with winreg.OpenKey(_hive(hive_name), subkey) as key:
            i = 0
            while True:
                try:
                    name, data, vtype = winreg.EnumValue(key, i)
                    # REG_BINARY and REG_NONE: hex-encode so changes are detectable
                    if vtype in (winreg.REG_BINARY, winreg.REG_NONE) and isinstance(data, (bytes, bytearray)):
                        result[name] = f"hex:{data.hex()}"
                    else:
                        result[name] = str(data)
                    i += 1
                except OSError:
                    break
        return result
    except FileNotFoundError:
        return {}
    except Exception as e:
        logger.debug(f"Registry read {hive_name}\\{subkey}: {e}")
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
        logger.warning(f"Registry FIM state save failed: {e}")


def _make_alert(
    hive: str, subkey: str, label: str, mitre: str,
    change_type: str, detail: str, extra: dict = None,
) -> Dict[str, Any]:
    reg_path = f"{hive}\\{subkey}"
    msg = f"REG-FIM [{change_type.upper()}] {label}: {detail}"
    logger.warning(msg)
    fields: Dict[str, Any] = {
        "event_type":       f"reg_{change_type}",
        "registry_path":    reg_path,
        "registry_label":   label,
        "mitre_technique":  mitre,
        "detail":           detail,
    }
    if extra:
        fields.update(extra)
    return {
        "timestamp":     _now(),
        "level":         "HIGH",
        "source":        "registry_fim",
        "message":       msg,
        "raw":           msg,
        "parsed_fields": fields,
    }


# ── Public API ────────────────────────────────────────────────────────────────

def initialize_registry_baseline():
    """Build initial registry snapshot. Call once at agent start."""
    if not IS_WINDOWS:
        return
    state = _load_state()
    changed = False
    for hive, subkey, _, _ in _WATCH_KEYS:
        key_id = f"{hive}\\{subkey}"
        if key_id not in state:
            state[key_id] = _read_key(hive, subkey)
            changed = True
    if changed:
        _save_state(state)
    logger.info(f"Registry FIM: baseline for {len(_WATCH_KEYS)} keys")


def check_registry_integrity() -> List[Dict[str, Any]]:
    """Compare current registry state against baseline. Returns alerts."""
    if not IS_WINDOWS:
        return []

    alerts: List[Dict[str, Any]] = []
    state   = _load_state()
    changed = False

    for hive, subkey, mitre, label in _WATCH_KEYS:
        key_id  = f"{hive}\\{subkey}"
        current = _read_key(hive, subkey)
        old     = state.get(key_id, None)

        if old is None:
            state[key_id] = current
            changed = True
            continue

        # Detect: new values added
        for name, val in current.items():
            if name not in old:
                alerts.append(_make_alert(
                    hive, subkey, label, mitre,
                    "value_added",
                    f"New value '{name}' = {val[:200]}",
                    {"reg_value_name": name, "reg_value_data": val[:500]},
                ))
                state[key_id][name] = val
                changed = True

        # Detect: values modified
        for name, old_val in old.items():
            if name in current and current[name] != old_val:
                alerts.append(_make_alert(
                    hive, subkey, label, mitre,
                    "value_modified",
                    f"Value '{name}' changed: {old_val[:100]} → {current[name][:100]}",
                    {
                        "reg_value_name": name,
                        "old_value": old_val[:500],
                        "new_value": current[name][:500],
                    },
                ))
                state[key_id][name] = current[name]
                changed = True

        # Detect: values deleted
        for name in list(old.keys()):
            if name not in current:
                alerts.append(_make_alert(
                    hive, subkey, label, mitre,
                    "value_deleted",
                    f"Value '{name}' deleted (was: {old.get(name, '')[:100]})",
                    {"reg_value_name": name, "old_value": old.get(name, '')[:500]},
                ))
                del state[key_id][name]
                changed = True

    if changed:
        _save_state(state)

    return alerts
