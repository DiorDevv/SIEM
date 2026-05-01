"""
Docker & Kubernetes Collector

Docker:
  - Container lifecycle events (start/stop/die/kill/oom)
  - Container log streaming (stdout/stderr)
  - Image pull/push/delete events
  - Network create/connect/disconnect events
  - Volume events
  - Docker daemon audit log

Kubernetes:
  - Pod log collection via kube API / kubectl
  - K8s audit log (kube-apiserver)
  - Pod lifecycle events (Pending/Running/Failed/OOMKilled)
  - Namespace activity
  - Secret/ConfigMap access events
  - RBAC events
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── MITRE ATT&CK mapping ──────────────────────────────────────────────────────
_MITRE_MAP: Dict[str, str] = {
    "container_escape":        "T1611",    # Escape to Host
    "privileged_container":    "T1611",    # Escape to Host
    "host_namespace":          "T1611",    # Escape to Host
    "image_tampering":         "T1525",    # Implant Internal Image
    "sensitive_mount":         "T1552.007",# Unsecured Credentials: Container API
    "exec_in_container":       "T1609",    # Container Administration Command
    "deploy_container":        "T1610",    # Deploy Container
    "build_image":             "T1612",    # Build Image on Host
    "network_scan":            "T1046",    # Network Service Discovery
    "secret_access":           "T1552",    # Unsecured Credentials
    "rbac_abuse":              "T1078.001",# Valid Accounts: Default Accounts
    "k8s_api_abuse":           "T1613",    # Container and Resource Discovery
    "lateral_movement":        "T1021",    # Remote Services
    "crypto_mining":           "T1496",    # Resource Hijacking
    "reverse_shell":           "T1059",    # Command and Scripting Interpreter
    "oom_kill":                "T1499",    # Endpoint Denial of Service
}

# ── Suspicious container image patterns ──────────────────────────────────────
_SUSPICIOUS_IMAGES = re.compile(
    r"(xmrig|monero|kinsing|cryptojack|miner|coinhive"
    r"|massdns|masscan|nmap|sqlmap|metasploit|beef"
    r"|weevely|cobltstrike|cobalt.strike"
    r"|alpine.*sh|busybox.*nc|scratch.*curl"
    r"|phpmyadmin/phpmyadmin|adminer)",
    re.IGNORECASE,
)

# ── Sensitive host paths that should never be bind-mounted ────────────────────
_DANGEROUS_MOUNTS = re.compile(
    r"^(/etc|/var/run/docker\.sock|/proc|/sys|/dev"
    r"|/root|/home|/boot|/lib|/usr/lib"
    r"|/var/lib/kubelet|/run/secrets/kubernetes\.io"
    r"|/etc/kubernetes|/etc/ssl/certs)",
    re.IGNORECASE,
)

# ── Reverse shell patterns inside container logs ──────────────────────────────
_REVERSE_SHELL = re.compile(
    r"(bash\s+-i\s+>&\s+/dev/tcp"
    r"|nc\s+-e\s+/bin"
    r"|python.*socket.*connect"
    r"|/dev/tcp/\d+\.\d+\.\d+\.\d+"
    r"|ncat\s+--exec"
    r"|socat\s+TCP"
    r"|mkfifo.*nc.*exec)",
    re.IGNORECASE,
)

# ── Crypto mining indicators ──────────────────────────────────────────────────
_CRYPTO_MINING = re.compile(
    r"(stratum\+tcp|pool\.minexmr|xmrig|nicehash"
    r"|coinhive\.min\.js|cryptonight|moneroocean"
    r"|hashrate\s*:\s*\d|accepted\s+shares)",
    re.IGNORECASE,
)

# ── K8s sensitive resource patterns ──────────────────────────────────────────
_K8S_SENSITIVE_RESOURCES = {"secrets", "serviceaccounts", "clusterrolebindings", "rolebindings"}
_K8S_SENSITIVE_VERBS      = {"create", "delete", "update", "patch", "escalate", "bind", "impersonate"}

# ── Docker socket path (platform-aware) ──────────────────────────────────────
import sys as _sys
if _sys.platform == "win32":
    DOCKER_SOCKET = r"\\.\pipe\docker_engine"
else:
    DOCKER_SOCKET = "/var/run/docker.sock"

# ── K8s config / token paths ─────────────────────────────────────────────────
K8S_TOKEN_PATH  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
K8S_CA_PATH     = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
K8S_NAMESPACE_F = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
K8S_API_SERVER  = os.environ.get("KUBERNETES_SERVICE_HOST", "")
K8S_API_PORT    = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _severity_from_status(status: str) -> str:
    mapping = {
        "die":    "high",
        "kill":   "high",
        "oom":    "critical",
        "exec":   "medium",
        "start":  "informational",
        "stop":   "informational",
        "create": "informational",
        "pull":   "low",
        "push":   "medium",
        "delete": "medium",
    }
    return mapping.get(status.lower(), "informational")


def _read_k8s_token() -> Optional[str]:
    try:
        with open(K8S_TOKEN_PATH) as f:
            return f.read().strip()
    except FileNotFoundError:
        return None


def _read_k8s_namespace() -> str:
    try:
        with open(K8S_NAMESPACE_F) as f:
            return f.read().strip()
    except FileNotFoundError:
        return "default"


# ── Docker via SDK or HTTP ────────────────────────────────────────────────────

async def _docker_request(path: str, timeout: int = 10) -> Optional[Any]:
    """Make HTTP request to Docker daemon via Unix socket (Linux/macOS) or named pipe (Windows)."""
    if not os.path.exists(DOCKER_SOCKET):
        return None
    try:
        import httpx
        if _sys.platform == "win32":
            # Windows: Docker Desktop exposes HTTP on localhost:2375 as fallback,
            # or use npipe transport if available. Try TCP first.
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(f"http://localhost:2375{path}")
                if resp.status_code == 200:
                    return resp.json()
        else:
            transport = httpx.AsyncHTTPTransport(uds=DOCKER_SOCKET)
            async with httpx.AsyncClient(transport=transport, timeout=timeout) as client:
                resp = await client.get(f"http://localhost{path}")
                if resp.status_code == 200:
                    return resp.json()
    except Exception as e:
        logger.debug(f"Docker socket request failed: {e}")
    return None


async def _get_containers() -> List[Dict[str, Any]]:
    data = await _docker_request("/containers/json?all=true")
    return data if isinstance(data, list) else []


async def _get_container_inspect(container_id: str) -> Optional[Dict[str, Any]]:
    return await _docker_request(f"/containers/{container_id}/json")


async def _get_docker_events(since: int) -> List[Dict[str, Any]]:
    """Fetch Docker events since Unix timestamp."""
    data = await _docker_request(f"/events?since={since}&until={int(time.time())}")
    if isinstance(data, list):
        return data
    # Docker events endpoint returns NDJSON; handle single dict or list
    if isinstance(data, dict):
        return [data]
    return []


async def _get_container_logs(container_id: str, tail: int = 100) -> str:
    """Fetch container stdout+stderr logs."""
    if not os.path.exists(DOCKER_SOCKET):
        return ""
    try:
        import httpx
        transport = httpx.AsyncHTTPTransport(uds=DOCKER_SOCKET)
        async with httpx.AsyncClient(transport=transport, timeout=15) as client:
            resp = await client.get(
                f"http://localhost/containers/{container_id}/logs"
                f"?stdout=true&stderr=true&tail={tail}&timestamps=true"
            )
            if resp.status_code == 200:
                # Docker log stream has 8-byte header per frame; strip it
                raw = resp.content
                lines = []
                i = 0
                while i + 8 <= len(raw):
                    frame_size = int.from_bytes(raw[i+4:i+8], "big")
                    i += 8
                    if i + frame_size <= len(raw):
                        lines.append(raw[i:i+frame_size].decode("utf-8", errors="replace"))
                    i += frame_size
                return "".join(lines)
    except Exception as e:
        logger.debug(f"Container logs fetch failed for {container_id}: {e}")
    return ""


# ── Container risk assessment ─────────────────────────────────────────────────

def _assess_container_risk(inspect: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Return (severity, threat_intel) based on container configuration."""
    ti: Dict[str, Any] = {}
    severity = "informational"
    risks = []

    host_config = inspect.get("HostConfig", {})
    config      = inspect.get("Config", {})
    image       = config.get("Image", "")

    # Privileged container
    if host_config.get("Privileged", False):
        risks.append("privileged_container")
        ti["mitre"]    = _MITRE_MAP["privileged_container"]
        severity       = "critical"
        ti["alert"]    = "Privileged container — host escape risk"

    # Host network namespace
    if host_config.get("NetworkMode") == "host":
        risks.append("host_namespace")
        ti["mitre"]    = _MITRE_MAP["host_namespace"]
        if severity != "critical":
            severity   = "high"

    # Host PID / IPC namespace
    if host_config.get("PidMode") == "host" or host_config.get("IpcMode") == "host":
        risks.append("host_namespace")
        if severity not in ("critical",):
            severity   = "high"

    # Dangerous bind mounts
    dangerous_mounts = []
    for bind in host_config.get("Binds", []) or []:
        host_path = bind.split(":")[0]
        if _DANGEROUS_MOUNTS.match(host_path):
            dangerous_mounts.append(host_path)
    if dangerous_mounts:
        risks.append("sensitive_mount")
        ti["dangerous_mounts"] = dangerous_mounts
        ti["mitre"]            = _MITRE_MAP["sensitive_mount"]
        if severity not in ("critical",):
            severity = "high"

    # Suspicious image
    if _SUSPICIOUS_IMAGES.search(image):
        risks.append("image_tampering")
        ti["mitre"]  = _MITRE_MAP["image_tampering"]
        ti["alert"]  = f"Suspicious image: {image}"
        severity     = "critical"

    # Capabilities added
    added_caps = host_config.get("CapAdd", []) or []
    if "SYS_ADMIN" in added_caps or "ALL" in added_caps:
        risks.append("container_escape")
        ti["mitre"]  = _MITRE_MAP["container_escape"]
        ti["cap_add"] = added_caps
        severity     = "critical"

    ti["risks"]    = risks
    ti["category"] = risks[0] if risks else "container_lifecycle"
    return severity, ti


# ── Docker event collector ────────────────────────────────────────────────────

async def collect_docker_events(
    since: Optional[int] = None,
    max_events: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Collect Docker daemon events and enrich with container metadata.
    """
    if not os.path.exists(DOCKER_SOCKET):
        logger.debug("Docker socket not found — skipping Docker collection")
        return []

    if since is None:
        since = int(time.time()) - 300

    events = await _get_docker_events(since)
    results = []

    for ev in events[:max_events]:
        action   = ev.get("Action", ev.get("status", ""))
        actor    = ev.get("Actor", {})
        attrs    = actor.get("Attributes", ev.get("from", {}))
        ev_type  = ev.get("Type", "container")
        ts       = ev.get("time", int(time.time()))
        ts_iso   = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

        container_id   = actor.get("ID", ev.get("id", ""))[:12]
        container_name = attrs.get("name", "") if isinstance(attrs, dict) else ""
        image          = attrs.get("image", "") if isinstance(attrs, dict) else str(attrs)

        event: Dict[str, Any] = {
            "timestamp":      ts_iso,
            "source":         "docker_events",
            "platform":       "docker",
            "log_type":       "container_event",
            "event_type":     ev_type,
            "action":         action,
            "container_id":   container_id,
            "container_name": container_name,
            "image":          image,
            "severity":       _severity_from_status(action),
            "threat_intel":   {},
            "raw":            json.dumps(ev),
        }

        # Enrich exec events
        if action in ("exec_create", "exec_start", "exec_die"):
            exec_cmd = attrs.get("execID", "") if isinstance(attrs, dict) else ""
            event["exec_command"] = exec_cmd
            event["severity"]     = "medium"
            event["threat_intel"] = {
                "category": "exec_in_container",
                "mitre":    _MITRE_MAP["exec_in_container"],
            }

        # Suspicious image
        if _SUSPICIOUS_IMAGES.search(image):
            event["severity"] = "critical"
            event["threat_intel"].update({
                "category": "image_tampering",
                "mitre":    _MITRE_MAP["image_tampering"],
                "alert":    f"Suspicious image launched: {image}",
            })

        results.append(event)

    return results


async def collect_container_logs(
    container_ids: Optional[List[str]] = None,
    tail: int = 200,
    max_containers: int = 50,
) -> List[Dict[str, Any]]:
    """
    Collect and analyze logs from running containers.
    """
    if not os.path.exists(DOCKER_SOCKET):
        return []

    if container_ids is None:
        containers = await _get_containers()
        container_ids = [c["Id"][:12] for c in containers[:max_containers]
                         if c.get("State") == "running"]

    results = []
    for cid in container_ids:
        log_text = await _get_container_logs(cid, tail)
        if not log_text:
            continue

        inspect   = await _get_container_inspect(cid)
        name      = ""
        image     = ""
        if inspect:
            name  = inspect.get("Name", "").lstrip("/")
            image = inspect.get("Config", {}).get("Image", "")
            sev, ti = _assess_container_risk(inspect)
            if ti.get("risks"):
                results.append({
                    "timestamp":      _now_iso(),
                    "source":         "docker_inspect",
                    "platform":       "docker",
                    "log_type":       "container_security",
                    "container_id":   cid,
                    "container_name": name,
                    "image":          image,
                    "severity":       sev,
                    "threat_intel":   ti,
                    "message":        f"Container risk: {', '.join(ti.get('risks', []))}",
                    "raw":            "",
                })

        for line in log_text.splitlines():
            if not line.strip():
                continue
            sev  = "informational"
            ti   = {}
            msg  = line

            if _REVERSE_SHELL.search(line):
                sev = "critical"
                ti  = {"category": "reverse_shell", "mitre": _MITRE_MAP["reverse_shell"],
                       "alert": "Reverse shell pattern in container log"}
            elif _CRYPTO_MINING.search(line):
                sev = "high"
                ti  = {"category": "crypto_mining", "mitre": _MITRE_MAP["crypto_mining"],
                       "alert": "Crypto mining activity detected"}
            elif re.search(r"(error|fail|exception|panic|fatal)", line, re.IGNORECASE):
                sev = "medium"

            results.append({
                "timestamp":      _now_iso(),
                "source":         "docker_logs",
                "platform":       "docker",
                "log_type":       "container_log",
                "container_id":   cid,
                "container_name": name,
                "image":          image,
                "severity":       sev,
                "message":        msg[:2048],
                "threat_intel":   ti,
                "raw":            line,
            })

    return results


# ── Kubernetes collector ──────────────────────────────────────────────────────

async def _k8s_request(path: str, token: str, timeout: int = 15) -> Optional[Any]:
    """Make request to Kubernetes API server."""
    if not K8S_API_SERVER:
        # Try kubectl if available
        return None
    try:
        import httpx
        import ssl
        ctx = ssl.create_default_context(cafile=K8S_CA_PATH if os.path.exists(K8S_CA_PATH) else None)
        url = f"https://{K8S_API_SERVER}:{K8S_API_PORT}{path}"
        async with httpx.AsyncClient(verify=ctx, timeout=timeout) as client:
            resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        logger.debug(f"K8s API request failed: {e}")
    return None


async def _kubectl(args: List[str], timeout: int = 15) -> Optional[str]:
    """Run kubectl command and return stdout."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "kubectl", *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode("utf-8", errors="replace")
    except (FileNotFoundError, asyncio.TimeoutError, Exception) as e:
        logger.debug(f"kubectl failed: {e}")
        return None


async def collect_k8s_pod_logs(
    namespace: str = "default",
    max_pods: int = 30,
    tail_lines: int = 100,
) -> List[Dict[str, Any]]:
    """
    Collect logs from Kubernetes pods using kubectl or in-cluster API.
    """
    results = []
    token = _read_k8s_token()

    # Get pod list
    pods_raw = None
    if token and K8S_API_SERVER:
        pods_raw = await _k8s_request(f"/api/v1/namespaces/{namespace}/pods", token)
    else:
        out = await _kubectl(["get", "pods", "-n", namespace, "-o", "json"])
        if out:
            try:
                pods_raw = json.loads(out)
            except json.JSONDecodeError:
                pass

    if not pods_raw:
        return results

    pods = pods_raw.get("items", [])[:max_pods]
    for pod in pods:
        meta     = pod.get("metadata", {})
        pod_name = meta.get("name", "")
        ns       = meta.get("namespace", namespace)
        phase    = pod.get("status", {}).get("phase", "")
        labels   = meta.get("labels", {})
        containers = pod.get("spec", {}).get("containers", [])

        # Assess pod security
        pod_spec = pod.get("spec", {})
        sec_ctx  = pod_spec.get("securityContext", {})
        risks    = []
        sev      = "informational"

        if pod_spec.get("hostPID") or pod_spec.get("hostIPC") or pod_spec.get("hostNetwork"):
            risks.append("host_namespace")
            sev = "high"

        for container in containers:
            c_sec = container.get("securityContext", {})
            if c_sec.get("privileged"):
                risks.append("privileged_container")
                sev = "critical"
            added = c_sec.get("capabilities", {}).get("add", [])
            if "SYS_ADMIN" in added or "ALL" in added:
                risks.append("container_escape")
                sev = "critical"
            for vol_mount in container.get("volumeMounts", []):
                path = vol_mount.get("mountPath", "")
                if _DANGEROUS_MOUNTS.match(path):
                    risks.append("sensitive_mount")
                    if sev != "critical":
                        sev = "high"

        if risks:
            results.append({
                "timestamp":      _now_iso(),
                "source":         "k8s_security",
                "platform":       "kubernetes",
                "log_type":       "pod_security",
                "namespace":      ns,
                "pod_name":       pod_name,
                "phase":          phase,
                "severity":       sev,
                "threat_intel": {
                    "risks":    risks,
                    "category": risks[0],
                    "mitre":    _MITRE_MAP.get(risks[0], "T1611"),
                    "labels":   labels,
                },
                "message": f"Pod security risk: {', '.join(risks)}",
                "raw":     "",
            })

        # OOMKilled pods
        for cs in pod.get("status", {}).get("containerStatuses", []):
            last = cs.get("lastState", {}).get("terminated", {})
            if last.get("reason") == "OOMKilled":
                results.append({
                    "timestamp":  _now_iso(),
                    "source":     "k8s_events",
                    "platform":   "kubernetes",
                    "log_type":   "pod_event",
                    "namespace":  ns,
                    "pod_name":   pod_name,
                    "severity":   "high",
                    "event_type": "OOMKilled",
                    "container":  cs.get("name", ""),
                    "threat_intel": {
                        "category": "oom_kill",
                        "mitre":    _MITRE_MAP["oom_kill"],
                    },
                    "message": f"Pod {pod_name} container OOMKilled",
                    "raw":     "",
                })

        # Collect pod logs
        for container in containers:
            cname = container.get("name", "")
            out = await _kubectl([
                "logs", pod_name, "-n", ns, "-c", cname,
                f"--tail={tail_lines}", "--timestamps=true",
            ])
            if not out:
                continue
            for line in out.splitlines():
                if not line.strip():
                    continue
                sev_line = "informational"
                ti_line  = {}
                if _REVERSE_SHELL.search(line):
                    sev_line = "critical"
                    ti_line  = {"category": "reverse_shell", "mitre": _MITRE_MAP["reverse_shell"],
                                "alert": "Reverse shell in pod log"}
                elif _CRYPTO_MINING.search(line):
                    sev_line = "high"
                    ti_line  = {"category": "crypto_mining", "mitre": _MITRE_MAP["crypto_mining"],
                                "alert": "Crypto mining in pod"}
                elif re.search(r"\b(error|fail|exception|panic|fatal)\b", line, re.IGNORECASE):
                    sev_line = "medium"

                results.append({
                    "timestamp":  _now_iso(),
                    "source":     "k8s_pod_logs",
                    "platform":   "kubernetes",
                    "log_type":   "pod_log",
                    "namespace":  ns,
                    "pod_name":   pod_name,
                    "container":  cname,
                    "severity":   sev_line,
                    "message":    line[:2048],
                    "threat_intel": ti_line,
                    "raw":        line,
                })

    return results


async def collect_k8s_audit_logs(
    audit_log_path: str = "/var/log/kubernetes/audit.log",
    tail_lines: int = 500,
) -> List[Dict[str, Any]]:
    """
    Parse Kubernetes API server audit log.
    Format: JSONL, one audit event per line.
    """
    results = []
    if not os.path.exists(audit_log_path):
        return results

    try:
        import subprocess
        out = subprocess.run(
            ["tail", "-n", str(tail_lines), audit_log_path],
            capture_output=True, text=True, timeout=10,
        ).stdout
    except Exception as e:
        logger.debug(f"K8s audit log read failed: {e}")
        return results

    for line in out.splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue

        verb       = ev.get("verb", "")
        resource   = ev.get("objectRef", {}).get("resource", "")
        ns         = ev.get("objectRef", {}).get("namespace", "")
        user       = ev.get("user", {}).get("username", "")
        source_ips = ev.get("sourceIPs", [])
        ts         = ev.get("requestReceivedTimestamp", _now_iso())

        sev = "informational"
        ti  = {}

        # Sensitive resource access
        if resource in _K8S_SENSITIVE_RESOURCES and verb in _K8S_SENSITIVE_VERBS:
            sev = "high"
            ti  = {
                "category": "secret_access" if resource == "secrets" else "rbac_abuse",
                "mitre":    _MITRE_MAP["secret_access"] if resource == "secrets" else _MITRE_MAP["rbac_abuse"],
                "user":     user,
                "verb":     verb,
                "resource": resource,
            }

        # API discovery (cluster-wide LIST requests)
        if verb == "list" and not ns:
            sev = "medium"
            ti.update({
                "category": "k8s_api_abuse",
                "mitre":    _MITRE_MAP["k8s_api_abuse"],
            })

        # Forbidden / unauthorized responses
        resp_code = ev.get("responseStatus", {}).get("code", 200)
        if resp_code in (401, 403):
            sev = "high"
            ti.update({"auth_error": True, "response_code": resp_code})

        results.append({
            "timestamp":   ts,
            "source":      "k8s_audit",
            "platform":    "kubernetes",
            "log_type":    "k8s_audit",
            "verb":        verb,
            "resource":    resource,
            "namespace":   ns,
            "user":        user,
            "source_ips":  source_ips,
            "response_code": resp_code,
            "severity":    sev,
            "threat_intel": ti,
            "message":     f"{user} {verb} {resource} in {ns or 'cluster'}",
            "raw":         line,
        })

    return results


async def collect_k8s_events(namespace: str = "default") -> List[Dict[str, Any]]:
    """Collect Kubernetes events (warnings/errors) via kubectl."""
    results = []
    out = await _kubectl([
        "get", "events", "-n", namespace,
        "--sort-by=.metadata.creationTimestamp",
        "-o", "json", "--field-selector=type=Warning",
    ])
    if not out:
        return results

    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return results

    for item in data.get("items", []):
        meta     = item.get("metadata", {})
        involved = item.get("involvedObject", {})
        reason   = item.get("reason", "")
        message  = item.get("message", "")
        count    = item.get("count", 1)
        ts       = item.get("lastTimestamp", _now_iso())

        sev = "high" if reason in ("OOMKilling", "BackOff", "Evicted", "FailedMount") else "medium"

        results.append({
            "timestamp":    ts,
            "source":       "k8s_events",
            "platform":     "kubernetes",
            "log_type":     "k8s_event",
            "namespace":    meta.get("namespace", namespace),
            "object_kind":  involved.get("kind", ""),
            "object_name":  involved.get("name", ""),
            "reason":       reason,
            "message":      message,
            "count":        count,
            "severity":     sev,
            "threat_intel": {
                "category": "oom_kill" if "OOM" in reason else "pod_event",
                "mitre":    _MITRE_MAP["oom_kill"] if "OOM" in reason else "",
            },
            "raw": json.dumps(item),
        })

    return results


# ── Main entry points ─────────────────────────────────────────────────────────

async def collect_docker(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Docker event and log collector.

    Config keys:
      events     (bool, default True)  — collect Docker events
      logs       (bool, default True)  — collect container logs
      since      (int)                 — Unix timestamp to collect events from
      max_events (int, default 1000)   — event limit
      tail       (int, default 200)    — log lines per container
    """
    since      = config.get("since")
    max_events = config.get("max_events", 1000)
    tail       = config.get("tail", 200)
    all_events: List[Dict[str, Any]] = []

    tasks = []
    if config.get("events", True):
        tasks.append(collect_docker_events(since, max_events))
    if config.get("logs", True):
        tasks.append(collect_container_logs(tail=tail))

    gathered = await asyncio.gather(*tasks, return_exceptions=True)
    for result in gathered:
        if isinstance(result, Exception):
            logger.warning(f"Docker collector error: {result}")
        elif isinstance(result, list):
            all_events.extend(result)

    logger.info(f"Docker collector: {len(all_events)} events")
    return all_events


async def collect_kubernetes(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Kubernetes pod log and event collector.

    Config keys:
      namespace    (str,  default "default")
      max_pods     (int,  default 30)
      tail_lines   (int,  default 100)
      audit_log    (str)               — path to K8s audit log
      pod_logs     (bool, default True)
      events       (bool, default True)
      audit        (bool, default True)
    """
    namespace  = config.get("namespace", "default")
    max_pods   = config.get("max_pods", 30)
    tail       = config.get("tail_lines", 100)
    audit_path = config.get("audit_log", "/var/log/kubernetes/audit.log")
    all_events: List[Dict[str, Any]] = []

    tasks = []
    if config.get("pod_logs", True):
        tasks.append(collect_k8s_pod_logs(namespace, max_pods, tail))
    if config.get("events", True):
        tasks.append(collect_k8s_events(namespace))
    if config.get("audit", True):
        tasks.append(collect_k8s_audit_logs(audit_path))

    gathered = await asyncio.gather(*tasks, return_exceptions=True)
    for result in gathered:
        if isinstance(result, Exception):
            logger.warning(f"K8s collector error: {result}")
        elif isinstance(result, list):
            all_events.extend(result)

    logger.info(f"Kubernetes collector: {len(all_events)} events")
    return all_events
