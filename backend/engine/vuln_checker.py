"""
Vulnerability checker using OSV.dev batch API (free, no key required).
Supports: PyPI, npm, Go, Maven, crates.io, RubyGems packages.
For system packages (apt/rpm) uses a hardcoded critical CVE seed.
"""
import logging
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

import aiohttp

logger = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_TIMEOUT      = aiohttp.ClientTimeout(total=20)

# Ecosystem normalisation
_ECOSYSTEM_MAP = {
    "pip":     "PyPI",
    "python":  "PyPI",
    "pypi":    "PyPI",
    "npm":     "npm",
    "nodejs":  "npm",
    "cargo":   "crates.io",
    "crates":  "crates.io",
    "go":      "Go",
    "maven":   "Maven",
    "rubygems":"RubyGems",
    "gem":     "RubyGems",
    "nuget":   "NuGet",
    "packagist": "Packagist",
}

# OSV-supported ecosystems only
_OSV_ECOSYSTEMS = {"PyPI", "npm", "Go", "Maven", "crates.io", "RubyGems", "NuGet", "Packagist", "Hex"}


def _norm_eco(eco: str) -> Optional[str]:
    return _ECOSYSTEM_MAP.get(eco.lower(), eco) if eco else None


def _severity_from_cvss(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _extract_cvss(osv_severity: list) -> Optional[float]:
    """Extract highest CVSS score from OSV severity list."""
    best = None
    for s in (osv_severity or []):
        stype = s.get("type", "")
        score_str = s.get("score", "")
        if "CVSS" in stype.upper():
            try:
                # Score can be a vector like "CVSS:3.1/AV:N/..." or just a number
                if "/" in score_str:
                    # Try to parse base score from the end or use severity label
                    pass
                else:
                    val = float(score_str)
                    if best is None or val > best:
                        best = val
            except (ValueError, TypeError):
                pass
    return best


async def check_packages(packages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Check a list of {name, version, ecosystem} against OSV.dev.
    Returns list of vulnerability dicts.
    """
    # Filter to OSV-supported ecosystems
    queries = []
    meta    = []   # parallel list to map back results
    for pkg in packages:
        eco  = _norm_eco(pkg.get("ecosystem", ""))
        name = pkg.get("name", "")
        ver  = pkg.get("version", "")
        if eco not in _OSV_ECOSYSTEMS or not name or not ver:
            continue
        queries.append({
            "version": ver,
            "package": {"name": name, "ecosystem": eco},
        })
        meta.append({"name": name, "version": ver, "ecosystem": eco})

    if not queries:
        return []

    # OSV batch: max 1000 per request
    results = []
    for i in range(0, len(queries), 1000):
        chunk = queries[i:i+1000]
        chunk_meta = meta[i:i+1000]
        try:
            async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
                async with session.post(
                    OSV_BATCH_URL,
                    json={"queries": chunk},
                ) as resp:
                    if resp.status != 200:
                        logger.error(f"OSV API error {resp.status}")
                        continue
                    data = await resp.json()
        except Exception as e:
            logger.error(f"OSV API request failed: {e}")
            continue

        for j, result in enumerate(data.get("results", [])):
            pkg_meta = chunk_meta[j]
            for vuln in result.get("vulns", []):
                cvss = _extract_cvss(vuln.get("severity", []))
                severity = _severity_from_cvss(cvss)

                # Find fixed version from affected[].ranges
                fixed_ver = None
                for affected in vuln.get("affected", []):
                    for rng in affected.get("ranges", []):
                        for event in rng.get("events", []):
                            if "fixed" in event:
                                fixed_ver = event["fixed"]
                                break

                refs = [r.get("url") for r in vuln.get("references", []) if r.get("url")][:5]

                results.append({
                    "package_name":    pkg_meta["name"],
                    "package_version": pkg_meta["version"],
                    "ecosystem":       pkg_meta["ecosystem"],
                    "vuln_id":         vuln.get("id", "UNKNOWN"),
                    "title":           vuln.get("summary", vuln.get("id", "")),
                    "description":     (vuln.get("details") or "")[:1000],
                    "severity":        severity,
                    "cvss_score":      cvss,
                    "fixed_version":   fixed_ver,
                    "references":      refs,
                })

    return results


async def check_all_packages(
    packages: List[Dict[str, Any]],
    distro: str = "ubuntu",
) -> List[Dict[str, Any]]:
    """
    Unified checker: OSV.dev for dev packages + NVD/USN for system packages.
    """
    from engine.nvd_checker import check_system_packages

    osv_task = check_packages(packages)
    nvd_task = check_system_packages(packages, distro=distro)

    osv_results, nvd_results = await asyncio.gather(osv_task, nvd_task, return_exceptions=True)

    combined = []
    if not isinstance(osv_results, Exception):
        combined.extend(osv_results)
    if not isinstance(nvd_results, Exception):
        combined.extend(nvd_results)

    # Deduplicate by (package_name + vuln_id)
    seen = set()
    unique = []
    for v in combined:
        key = (v.get("package_name", ""), v.get("vuln_id", ""))
        if key not in seen:
            seen.add(key)
            unique.append(v)

    logger.info(f"Total vulnerabilities found: {len(unique)} "
                f"(OSV: {len(osv_results) if not isinstance(osv_results, Exception) else 0}, "
                f"NVD/USN: {len(nvd_results) if not isinstance(nvd_results, Exception) else 0})")
    return unique
