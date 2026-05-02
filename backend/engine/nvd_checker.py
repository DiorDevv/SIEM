"""
NVD (NIST) CVE checker for system packages (apt/dpkg, rpm/yum).
Uses NVD REST API v2 — free, 5 req/s without key, 50/s with key.
Also checks Ubuntu Security Notices (USN) for Debian/Ubuntu packages.

API docs: https://nvd.nist.gov/developers/vulnerabilities
"""
import logging
import asyncio
import re
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

import aiohttp

logger = logging.getLogger(__name__)

_NVD_API  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_USN_API  = "https://ubuntu.com/security/cves.json"
_TIMEOUT  = aiohttp.ClientTimeout(total=15)
_CACHE_TTL = timedelta(hours=12)
_cache: Dict[str, tuple] = {}

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MEDIUM":   "MEDIUM",
    "LOW":      "LOW",
    "NONE":     "LOW",
}


def _severity_from_cvss(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"


def _normalize_package_name(name: str, ecosystem: str) -> str:
    """Normalize package name for CPE matching."""
    name = name.lower().strip()
    # Common renamings
    aliases = {
        "python3": "python",
        "libssl-dev": "openssl",
        "libssl1.1": "openssl",
        "libc6": "glibc",
        "libgnutls30": "gnutls",
    }
    return aliases.get(name, name)


async def _query_nvd(keyword: str, version: str) -> List[Dict[str, Any]]:
    from config import settings
    cache_key = f"nvd:{keyword}:{version}"

    if cache_key in _cache:
        data, expiry = _cache[cache_key]
        if datetime.utcnow() < expiry:
            return data

    headers = {"Content-Type": "application/json"}
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY

    params = {
        "keywordSearch": keyword,
        "keywordExactMatch": "",
        "resultsPerPage": 20,
    }

    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.get(_NVD_API, headers=headers, params=params) as resp:
                if resp.status == 403:
                    logger.warning("NVD API rate limited — consider setting NVD_API_KEY")
                    return []
                if resp.status != 200:
                    logger.debug(f"NVD API {resp.status} for {keyword}")
                    return []
                data = await resp.json()
    except asyncio.TimeoutError:
        logger.debug(f"NVD timeout for {keyword}")
        return []
    except Exception as e:
        logger.debug(f"NVD error: {e}")
        return []

    vulns = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        # Get CVSS score
        cvss_score = None
        severity   = "UNKNOWN"
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss_data = m.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                sev_str    = cvss_data.get("baseSeverity") or m.get("baseSeverity", "")
                severity   = SEVERITY_MAP.get(sev_str.upper(), _severity_from_cvss(cvss_score))
                break

        # Check if version is affected
        affected_versions = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        ver_end   = match.get("versionEndIncluding") or match.get("versionEndExcluding")
                        ver_start = match.get("versionStartIncluding") or match.get("versionStartExcluding")
                        if ver_end:
                            affected_versions.append(ver_end)
                        cpe = match.get("criteria", "")
                        if keyword.lower() in cpe.lower():
                            affected_versions.append(cpe)

        # Description
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")[:500]
                break

        # References
        refs = [r.get("url", "") for r in cve.get("references", [])[:3]]

        # Published date
        published = cve.get("published", "")

        vulns.append({
            "vuln_id":         cve_id,
            "title":           f"{cve_id} - {keyword} {version}",
            "description":     desc,
            "severity":        severity,
            "cvss_score":      cvss_score,
            "fixed_version":   None,
            "references":      refs,
            "published":       published,
            "affected_versions": affected_versions,
            "source":          "nvd",
        })

    # Rate limiting — 5 req/s without key
    if not settings.NVD_API_KEY:
        await asyncio.sleep(0.2)

    _cache[cache_key] = (vulns, datetime.utcnow() + _CACHE_TTL)
    return vulns


async def _query_ubuntu_usn(package: str) -> List[Dict[str, Any]]:
    """Query Ubuntu Security Notices for a package."""
    cache_key = f"usn:{package}"
    if cache_key in _cache:
        data, expiry = _cache[cache_key]
        if datetime.utcnow() < expiry:
            return data

    url = f"https://ubuntu.com/security/cves.json?package={package}&limit=10"
    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json(content_type=None)
    except Exception as e:
        logger.debug(f"USN error for {package}: {e}")
        return []

    vulns = []
    for cve in data.get("cves", []):
        cve_id   = cve.get("id", "")
        severity = cve.get("ubuntu_priority", "UNKNOWN").upper()
        severity = SEVERITY_MAP.get(severity, "MEDIUM")

        # Extract fixed version
        fixed = None
        for pkg_status in cve.get("packages", []):
            if pkg_status.get("name") == package:
                for release in pkg_status.get("statuses", []):
                    if release.get("status") == "released":
                        fixed = release.get("description")
                        break

        vulns.append({
            "vuln_id":       cve_id,
            "title":         cve.get("description", cve_id)[:200],
            "description":   cve.get("description", "")[:500],
            "severity":      severity,
            "cvss_score":    None,
            "fixed_version": fixed,
            "references":    [f"https://ubuntu.com/security/{cve_id}"],
            "source":        "ubuntu_usn",
        })

    _cache[cache_key] = (vulns, datetime.utcnow() + _CACHE_TTL)
    return vulns


async def check_system_packages(
    packages: List[Dict[str, Any]],
    distro: str = "ubuntu",
) -> List[Dict[str, Any]]:
    """
    Check system packages (apt/deb, rpm) for CVEs.
    packages: list of {name, version, ecosystem}
    Returns list of vulnerability dicts.
    """
    from config import settings
    if not settings.NVD_ENABLED:
        return []

    results = []
    # Process in small batches to respect rate limits
    batch_size = 5
    pkg_list = [p for p in packages
                if p.get("ecosystem", "").lower() in ("deb", "rpm", "dpkg", "apt", "yum", "dnf", "unknown", "")
                and p.get("name") and p.get("version")]

    # Limit to interesting packages (skip base ones that rarely have CVEs)
    _SKIP_PREFIXES = ("lib", "fonts-", "language-", "locales", "python3-doc",
                      "perl-doc", "doc-", "manpages")
    interesting = [p for p in pkg_list
                   if not any(p["name"].startswith(pfx) for pfx in _SKIP_PREFIXES)][:50]

    for i in range(0, len(interesting), batch_size):
        batch = interesting[i:i+batch_size]
        tasks = []
        for pkg in batch:
            name = _normalize_package_name(pkg["name"], pkg.get("ecosystem", ""))
            ver  = pkg["version"]

            if distro in ("ubuntu", "debian"):
                tasks.append(_query_ubuntu_usn(name))
            else:
                tasks.append(_query_nvd(name, ver))

        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        for j, pkg_vulns in enumerate(batch_results):
            if isinstance(pkg_vulns, Exception) or not pkg_vulns:
                continue
            pkg = batch[j]
            for v in pkg_vulns:
                results.append({
                    "package_name":    pkg["name"],
                    "package_version": pkg["version"],
                    "ecosystem":       pkg.get("ecosystem", "deb"),
                    **v,
                })

    logger.info(f"NVD/USN check: {len(interesting)} packages → {len(results)} findings")
    return results
