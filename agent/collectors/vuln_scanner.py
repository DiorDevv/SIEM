"""
Vulnerability scanner — collects installed packages from the system.
Supports: dpkg (Debian/Ubuntu), rpm (RHEL/CentOS), pip, npm, Windows registry.
Packages are sent to the server which checks them against OSV.dev.
"""
import sys
import json
import logging
import subprocess
import re
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == "win32"


def _run(cmd: List[str], timeout: int = 30) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return ""


# ── Collectors ────────────────────────────────────────────────────────────────

def _collect_dpkg() -> List[Dict[str, Any]]:
    out = _run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
    packages = []
    for line in out.splitlines():
        parts = line.strip().split("\t")
        if len(parts) == 2 and parts[1] and parts[1] != "<none>":
            packages.append({"name": parts[0], "version": parts[1], "ecosystem": "apt"})
    return packages


def _collect_rpm() -> List[Dict[str, Any]]:
    out = _run(["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
    packages = []
    for line in out.splitlines():
        parts = line.strip().split("\t")
        if len(parts) == 2:
            packages.append({"name": parts[0], "version": parts[1], "ecosystem": "rpm"})
    return packages


def _collect_pip() -> List[Dict[str, Any]]:
    # Try pip list --format=json first
    out = _run([sys.executable, "-m", "pip", "list", "--format=json"])
    if out.strip():
        try:
            pkgs = json.loads(out)
            return [{"name": p["name"], "version": p["version"], "ecosystem": "pip"}
                    for p in pkgs if p.get("name") and p.get("version")]
        except Exception:
            pass
    # Fallback: pip list plain
    out = _run([sys.executable, "-m", "pip", "list"])
    packages = []
    for line in out.splitlines()[2:]:   # skip header
        parts = line.split()
        if len(parts) >= 2:
            packages.append({"name": parts[0], "version": parts[1], "ecosystem": "pip"})
    return packages


def _collect_npm_global() -> List[Dict[str, Any]]:
    out = _run(["npm", "list", "-g", "--json", "--depth=0"])
    packages = []
    try:
        data = json.loads(out)
        for name, info in (data.get("dependencies") or {}).items():
            ver = info.get("version", "")
            if ver:
                packages.append({"name": name, "version": ver, "ecosystem": "npm"})
    except Exception:
        pass
    return packages


def _collect_windows_registry() -> List[Dict[str, Any]]:
    """Read installed software from Windows registry."""
    try:
        import winreg
    except ImportError:
        return []

    packages = []
    keys = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]
    for key_path in keys:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, subkey_name)
                    try:
                        name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                        version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                        if name and version:
                            packages.append({"name": name, "version": version, "ecosystem": "windows"})
                    except FileNotFoundError:
                        pass
                    winreg.CloseKey(subkey)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except OSError:
            pass
    return packages


# ── Main entry ────────────────────────────────────────────────────────────────

def collect_packages() -> List[Dict[str, Any]]:
    """Collect all installed packages. Returns deduplicated list."""
    packages = []

    if IS_WINDOWS:
        packages += _collect_windows_registry()
    else:
        # Try dpkg (Debian/Ubuntu)
        if _run(["which", "dpkg-query"]).strip():
            packages += _collect_dpkg()
        # Try rpm (RHEL/CentOS/Fedora)
        elif _run(["which", "rpm"]).strip():
            packages += _collect_rpm()

    # Always collect pip packages
    packages += _collect_pip()

    # Try npm global packages
    if _run(["which", "npm"]).strip():
        packages += _collect_npm_global()

    # Deduplicate by (name, version, ecosystem)
    seen = set()
    result = []
    for p in packages:
        key = (p["name"].lower(), p["version"], p["ecosystem"])
        if key not in seen:
            seen.add(key)
            result.append(p)

    logger.info(f"VulnScanner: collected {len(result)} packages")
    return result
