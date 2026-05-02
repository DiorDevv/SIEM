"""
Offline Log Buffer — SQLite-backed persistent queue.

When the SIEM server is unreachable, log batches are stored here.
When the server comes back, buffered logs are drained in FIFO order
before new logs are sent.

Features:
  - Thread-safe (WAL mode + threading.Lock)
  - Gzip compression (5-10x space reduction in SQLite)
  - Configurable max entries and TTL
  - Automatic eviction of oldest entries when full
  - Server health tracker with exponential backoff
"""
import gzip
import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

logger = logging.getLogger("siem-agent.buffer")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS log_queue (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id   TEXT    NOT NULL,
    logs_gz    BLOB    NOT NULL,
    log_count  INTEGER NOT NULL DEFAULT 0,
    created_at REAL    NOT NULL,
    retries    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_created ON log_queue (created_at);
"""


class LogBuffer:
    """
    Persistent SQLite queue for offline log buffering.

    Usage:
        buf = LogBuffer('/opt/siem-agent/buffer.db')
        buf.push(agent_id, logs)               # store on send failure
        for batch_id, aid, logs in buf.drain(5):
            if send_ok:
                buf.ack(batch_id)
            else:
                buf.increment_retry(batch_id)
        buf.close()
    """

    def __init__(
        self,
        db_path: str,
        max_batches: int = 2000,   # ~200k logs at batch_size=100
        ttl_hours: int = 48,       # drop logs older than 48h
    ):
        self.db_path    = db_path
        self.max_batches = max_batches
        self.ttl_hours  = ttl_hours
        self._lock      = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._init()

    # ── Init ──────────────────────────────────────────────────────────────────

    def _init(self):
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            timeout=10,
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA cache_size=-4000")   # 4 MB page cache
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        count = self._conn.execute("SELECT COUNT(*) FROM log_queue").fetchone()[0]
        if count:
            logger.info(f"Buffer: loaded {count} queued batch(es) from disk")

    # ── Write ─────────────────────────────────────────────────────────────────

    def push(self, agent_id: str, logs: List[dict]) -> bool:
        """Compress and store a log batch. Returns True on success."""
        if not logs:
            return True
        try:
            compressed = gzip.compress(
                json.dumps(logs, separators=(',', ':')).encode(),
                compresslevel=6,
            )
            with self._lock:
                self._evict()
                self._conn.execute(
                    "INSERT INTO log_queue (agent_id, logs_gz, log_count, created_at)"
                    " VALUES (?, ?, ?, ?)",
                    (agent_id, compressed, len(logs), datetime.utcnow().timestamp()),
                )
                self._conn.commit()
            logger.debug(f"Buffer: queued {len(logs)} logs ({len(compressed)} bytes gzip)")
            return True
        except Exception as e:
            logger.error(f"Buffer push failed: {e}")
            return False

    # ── Read ──────────────────────────────────────────────────────────────────

    def drain(self, batch_limit: int = 10) -> List[Tuple[int, str, List[dict]]]:
        """
        Return up to batch_limit oldest batches for retry.
        Does NOT remove them — call ack() after successful send.
        """
        result: List[Tuple[int, str, List[dict]]] = []
        try:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT id, agent_id, logs_gz FROM log_queue"
                    " ORDER BY created_at ASC LIMIT ?",
                    (batch_limit,),
                ).fetchall()
            for row_id, aid, gz_data in rows:
                try:
                    logs = json.loads(gzip.decompress(gz_data))
                    result.append((row_id, aid, logs))
                except Exception as e:
                    logger.warning(f"Buffer: corrupt batch id={row_id}, dropping: {e}")
                    self.ack(row_id)
        except Exception as e:
            logger.error(f"Buffer drain error: {e}")
        return result

    def ack(self, batch_id: int):
        """Remove a successfully-sent batch."""
        try:
            with self._lock:
                self._conn.execute(
                    "DELETE FROM log_queue WHERE id = ?", (batch_id,)
                )
                self._conn.commit()
        except Exception as e:
            logger.error(f"Buffer ack error: {e}")

    def increment_retry(self, batch_id: int):
        """Increment retry counter for a failed send attempt."""
        try:
            with self._lock:
                self._conn.execute(
                    "UPDATE log_queue SET retries = retries + 1 WHERE id = ?",
                    (batch_id,),
                )
                self._conn.commit()
        except Exception:
            pass

    # ── Maintenance ───────────────────────────────────────────────────────────

    def _evict(self):
        """Called inside lock. Remove expired + overflow entries."""
        cutoff = (datetime.utcnow() - timedelta(hours=self.ttl_hours)).timestamp()
        self._conn.execute(
            "DELETE FROM log_queue WHERE created_at < ?", (cutoff,)
        )
        # Enforce max_batches by dropping oldest
        overflow = (
            self._conn.execute("SELECT COUNT(*) FROM log_queue").fetchone()[0]
            - self.max_batches
        )
        if overflow > 0:
            self._conn.execute(
                "DELETE FROM log_queue WHERE id IN"
                " (SELECT id FROM log_queue ORDER BY created_at ASC LIMIT ?)",
                (overflow,),
            )
            logger.warning(f"Buffer full — dropped {overflow} oldest batch(es)")
        self._conn.commit()

    @property
    def size(self) -> int:
        try:
            with self._lock:
                return self._conn.execute(
                    "SELECT COUNT(*) FROM log_queue"
                ).fetchone()[0]
        except Exception:
            return 0

    @property
    def total_logs(self) -> int:
        try:
            with self._lock:
                return self._conn.execute(
                    "SELECT COALESCE(SUM(log_count), 0) FROM log_queue"
                ).fetchone()[0]
        except Exception:
            return 0

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None


# ── Server Health Tracker ─────────────────────────────────────────────────────

class ServerHealth:
    """
    Tracks server up/down state.
    Implements exponential backoff so we don't hammer a downed server.

    Backoff schedule (seconds): 5, 10, 20, 40, 80, 120, 120, ...
    """

    _BACKOFF = [5, 10, 20, 40, 80, 120]

    def __init__(self):
        self._up          = True
        self._fail_streak = 0
        self._retry_after = 0.0   # monotonic timestamp
        self._down_since: Optional[datetime] = None
        self._lock = threading.Lock()

    def mark_success(self) -> bool:
        """Call on successful HTTP response. Returns True if server just recovered."""
        with self._lock:
            was_down = not self._up
            self._up          = True
            self._fail_streak = 0
            self._retry_after = 0.0
            if was_down:
                downtime = (datetime.utcnow() - self._down_since).total_seconds() if self._down_since else 0
                logger.info(f"Server reconnected (was down {downtime:.0f}s)")
                self._down_since = None
            return was_down

    def mark_failure(self):
        """Call on connection error or 5xx response."""
        with self._lock:
            if self._up:
                self._down_since = datetime.utcnow()
                logger.warning("Server appears unreachable — buffering logs locally")
            self._up = False
            self._fail_streak += 1
            delay = self._BACKOFF[min(self._fail_streak - 1, len(self._BACKOFF) - 1)]
            import time
            self._retry_after = time.monotonic() + delay
            logger.debug(f"Server down (streak={self._fail_streak}), next retry in {delay}s")

    @property
    def is_up(self) -> bool:
        with self._lock:
            return self._up

    def should_retry(self) -> bool:
        """True when backoff window has elapsed and we should attempt a send."""
        import time
        with self._lock:
            return self._up or time.monotonic() >= self._retry_after

    @property
    def down_since(self) -> Optional[datetime]:
        with self._lock:
            return self._down_since
