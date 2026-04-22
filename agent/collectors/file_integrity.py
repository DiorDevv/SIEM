"""
Professional File Integrity Monitor (FIM).
Detects: file modification, creation, deletion, permission changes.
"""
import os
import stat
import hashlib
import logging
import json
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

_STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '.fim_state.json')


class FileState:
    __slots__ = ('hash', 'size', 'mtime', 'mode', 'uid', 'gid')

    def __init__(self, hash_: str, size: int, mtime: float, mode: int, uid: int, gid: int):
        self.hash  = hash_
        self.size  = size
        self.mtime = mtime
        self.mode  = mode
        self.uid   = uid
        self.gid   = gid

    def to_dict(self) -> dict:
        return {
            'hash': self.hash, 'size': self.size, 'mtime': self.mtime,
            'mode': self.mode, 'uid':  self.uid,  'gid':   self.gid,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'FileState':
        return cls(d['hash'], d['size'], d['mtime'], d['mode'], d.get('uid', 0), d.get('gid', 0))


# In-memory baseline: path → FileState
_baseline: Dict[str, FileState] = {}


# ── Persistence ───────────────────────────────────────────────────────────────

def _load_state():
    global _baseline
    if os.path.exists(_STATE_FILE):
        try:
            with open(_STATE_FILE) as f:
                data = json.load(f)
            _baseline = {k: FileState.from_dict(v) for k, v in data.items()}
            logger.info(f"FIM: loaded {len(_baseline)} baseline entries")
        except Exception as e:
            logger.warning(f"FIM: could not load state: {e}")


def _save_state():
    try:
        with open(_STATE_FILE, 'w') as f:
            json.dump({k: v.to_dict() for k, v in _baseline.items()}, f, indent=2)
    except Exception as e:
        logger.warning(f"FIM: could not save state: {e}")


# ── Hashing ───────────────────────────────────────────────────────────────────

def _sha256(path: str) -> Optional[str]:
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except PermissionError:
        logger.warning(f"FIM: permission denied reading {path}")
        return None
    except FileNotFoundError:
        return None
    except Exception as e:
        logger.error(f"FIM hash error {path}: {e}")
        return None


def _get_file_state(path: str) -> Optional[FileState]:
    try:
        st    = os.stat(path)
        hash_ = _sha256(path)
        if hash_ is None:
            return None
        return FileState(
            hash_=hash_,
            size=st.st_size,
            mtime=st.st_mtime,
            mode=st.st_mode,
            uid=st.st_uid,
            gid=st.st_gid,
        )
    except FileNotFoundError:
        return None
    except Exception as e:
        logger.error(f"FIM stat error {path}: {e}")
        return None


def _mode_str(mode: int) -> str:
    return stat.filemode(mode)


def _make_alert(path: str, event: str, severity: str, detail: str, extra: dict = None) -> Dict[str, Any]:
    msg = f"FIM [{event.upper()}] {path} — {detail}"
    logger.warning(msg)
    fields: Dict[str, Any] = {
        'event_type': f'fim_{event}',
        'file_path':  path,
        'detail':     detail,
    }
    if extra:
        fields.update(extra)
    return {
        'timestamp':     datetime.now(timezone.utc).isoformat(),
        'level':         severity,
        'source':        'fim',
        'message':       msg,
        'raw':           msg,
        'parsed_fields': fields,
    }


# ── Public interface ──────────────────────────────────────────────────────────

def initialize_baselines(paths: List[str]):
    """Build initial baseline for all monitored paths."""
    _load_state()
    new_paths = 0
    for path in paths:
        if path in _baseline:
            continue
        state = _get_file_state(path)
        if state:
            _baseline[path] = state
            new_paths += 1
            logger.debug(f"FIM baseline: {path} [{state.hash[:12]}...]")
        else:
            if not os.path.exists(path):
                logger.debug(f"FIM: path not found (will alert if created): {path}")
    if new_paths:
        _save_state()
    logger.info(f"FIM ready — monitoring {len(_baseline)} files")


def check_file_integrity(paths: List[str]) -> List[Dict[str, Any]]:
    """
    Compare current state against baseline.
    Returns list of alert log dicts for any changes found.
    """
    alerts: List[Dict[str, Any]] = []
    changed = False

    for path in paths:
        exists  = os.path.exists(path)
        known   = path in _baseline
        current = _get_file_state(path) if exists else None

        # ── File deleted ─────────────────────────────────────────────────────
        if known and not exists:
            old = _baseline.pop(path)
            alerts.append(_make_alert(
                path, 'deleted', 'CRITICAL',
                f"File was deleted (last hash: {old.hash[:16]}...)",
                {'old_hash': old.hash, 'old_size': old.size},
            ))
            changed = True
            continue

        # ── New file appeared ─────────────────────────────────────────────────
        if not known and exists and current:
            _baseline[path] = current
            alerts.append(_make_alert(
                path, 'created', 'WARNING',
                f"New file detected — hash: {current.hash[:16]}... "
                f"size: {current.size}B mode: {_mode_str(current.mode)}",
                {'new_hash': current.hash, 'new_size': current.size,
                 'mode': _mode_str(current.mode)},
            ))
            changed = True
            continue

        if not current:
            continue

        old = _baseline[path]

        # ── Content changed ───────────────────────────────────────────────────
        if current.hash != old.hash:
            alerts.append(_make_alert(
                path, 'modified', 'CRITICAL',
                f"Content changed — "
                f"old: {old.hash[:16]}... → new: {current.hash[:16]}... "
                f"size: {old.size}→{current.size}B",
                {
                    'old_hash': old.hash,
                    'new_hash': current.hash,
                    'old_size': old.size,
                    'new_size': current.size,
                },
            ))
            _baseline[path] = current
            changed = True
            continue

        # ── Permissions changed ───────────────────────────────────────────────
        if current.mode != old.mode:
            alerts.append(_make_alert(
                path, 'permissions_changed', 'WARNING',
                f"Permissions changed: {_mode_str(old.mode)} → {_mode_str(current.mode)}",
                {'old_mode': _mode_str(old.mode), 'new_mode': _mode_str(current.mode)},
            ))
            _baseline[path] = current
            changed = True
            continue

        # ── Ownership changed ─────────────────────────────────────────────────
        if current.uid != old.uid or current.gid != old.gid:
            alerts.append(_make_alert(
                path, 'ownership_changed', 'WARNING',
                f"Ownership changed: uid {old.uid}→{current.uid} gid {old.gid}→{current.gid}",
                {'old_uid': old.uid, 'new_uid': current.uid,
                 'old_gid': old.gid, 'new_gid': current.gid},
            ))
            _baseline[path] = current
            changed = True

    if changed:
        _save_state()

    return alerts
