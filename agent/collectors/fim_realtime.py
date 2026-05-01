"""
Real-time File Integrity Monitor.
  Linux:   inotify via ctypes (no extra deps)
  Windows: ReadDirectoryChangesW via watchdog library
  macOS:   FSEvents via watchdog library
Puts events into a shared Queue for the main agent loop.
"""
import os
import struct
import ctypes
import ctypes.util
import select
import threading
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from queue import Queue, Full

logger = logging.getLogger(__name__)

# ── inotify constants ─────────────────────────────────────────────────────────

IN_MODIFY      = 0x00000002
IN_ATTRIB      = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM  = 0x00000040
IN_MOVED_TO    = 0x00000080
IN_CREATE      = 0x00000100
IN_DELETE      = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF   = 0x00000800
IN_IGNORED     = 0x00008000
IN_ISDIR       = 0x40000000

WATCH_MASK = (IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE |
              IN_CREATE | IN_DELETE | IN_DELETE_SELF |
              IN_MOVED_FROM | IN_MOVED_TO | IN_MOVE_SELF)

_FLAG_NAMES: Dict[int, str] = {
    IN_MODIFY:      'MODIFY',
    IN_ATTRIB:      'ATTRIB',
    IN_CLOSE_WRITE: 'CLOSE_WRITE',
    IN_CREATE:      'CREATE',
    IN_DELETE:      'DELETE',
    IN_DELETE_SELF: 'DELETE_SELF',
    IN_MOVED_FROM:  'MOVED_FROM',
    IN_MOVED_TO:    'MOVED_TO',
    IN_MOVE_SELF:   'MOVE_SELF',
}

_SEVERITY: Dict[str, str] = {
    'MODIFY':      'CRITICAL',
    'CLOSE_WRITE': 'CRITICAL',
    'DELETE':      'CRITICAL',
    'DELETE_SELF': 'CRITICAL',
    'ATTRIB':      'WARNING',
    'CREATE':      'WARNING',
    'MOVED_FROM':  'WARNING',
    'MOVED_TO':    'WARNING',
    'MOVE_SELF':   'WARNING',
}

_EVENT_TYPE: Dict[str, str] = {
    'MODIFY':      'fim_modified',
    'CLOSE_WRITE': 'fim_modified',
    'ATTRIB':      'fim_attrib_changed',
    'CREATE':      'fim_created',
    'DELETE':      'fim_deleted',
    'DELETE_SELF': 'fim_deleted',
    'MOVED_FROM':  'fim_moved',
    'MOVED_TO':    'fim_moved',
    'MOVE_SELF':   'fim_moved',
}

_EVENT_STRUCT  = 'iIII'
_EVENT_SIZE    = struct.calcsize(_EVENT_STRUCT)
_READ_BUF      = 65536


# ── inotify wrapper ───────────────────────────────────────────────────────────

class _Inotify:
    def __init__(self):
        libc_name = ctypes.util.find_library('c') or 'libc.so.6'
        self._lib = ctypes.CDLL(libc_name, use_errno=True)
        self._lib.inotify_init.restype        = ctypes.c_int
        self._lib.inotify_add_watch.restype   = ctypes.c_int
        self._lib.inotify_add_watch.argtypes  = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        self._lib.inotify_rm_watch.restype    = ctypes.c_int
        self._lib.inotify_rm_watch.argtypes   = [ctypes.c_int, ctypes.c_int]
        self.fd = self._lib.inotify_init()
        if self.fd < 0:
            raise OSError(f"inotify_init failed: errno={ctypes.get_errno()}")

    def add_watch(self, path: str, mask: int) -> int:
        wd = self._lib.inotify_add_watch(self.fd, path.encode(), mask)
        if wd < 0:
            raise OSError(f"inotify_add_watch({path}) errno={ctypes.get_errno()}")
        return wd

    def rm_watch(self, wd: int):
        self._lib.inotify_rm_watch(self.fd, wd)

    def read_events(self) -> List[Tuple[int, int, int, str]]:
        """Returns list of (wd, mask, cookie, name)."""
        events = []
        try:
            raw = os.read(self.fd, _READ_BUF)
        except OSError:
            return events
        offset = 0
        while offset + _EVENT_SIZE <= len(raw):
            wd, mask, cookie, name_len = struct.unpack_from(_EVENT_STRUCT, raw, offset)
            offset += _EVENT_SIZE
            name = ''
            if name_len > 0 and offset + name_len <= len(raw):
                name = raw[offset:offset + name_len].rstrip(b'\x00').decode('utf-8', errors='replace')
                offset += name_len
            events.append((wd, mask, cookie, name))
        return events

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass


# ── FIM watch entry ───────────────────────────────────────────────────────────

class _Watch:
    """Maps a watch descriptor back to monitored paths."""
    __slots__ = ('dir_path', 'file_filter')

    def __init__(self, dir_path: str, file_filter: Optional[str] = None):
        self.dir_path    = dir_path     # actual directory being watched
        self.file_filter = file_filter  # if set, only report this filename


# ── Public class ──────────────────────────────────────────────────────────────

class RealtimeFIM:
    """
    Real-time FIM backed by inotify.

    Usage:
        q = Queue()
        fim = RealtimeFIM(['/etc/passwd', '/etc/hosts', '/etc'], q)
        if fim.start():
            # events arrive in q as standard log dicts
    """

    def __init__(self, paths: List[str], event_queue: Queue, queue_maxsize: int = 2000):
        self._paths      = paths
        self._queue      = event_queue
        self._ino: Optional[_Inotify] = None
        self._watches: Dict[int, _Watch] = {}
        self._stop       = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> bool:
        import sys
        if sys.platform == 'win32' or sys.platform == 'darwin':
            return self._start_watchdog()
        return self._start_inotify()

    def _start_watchdog(self) -> bool:
        """Windows/macOS: use watchdog for ReadDirectoryChangesW / FSEvents."""
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler

            queue_ref = self._queue
            severity_map  = _SEVERITY
            etype_map     = _EVENT_TYPE

            class _Handler(FileSystemEventHandler):
                def _emit(self, event_type: str, path: str, is_dir: bool):
                    flag     = event_type.upper()
                    severity = severity_map.get(flag, 'WARNING')
                    etype    = etype_map.get(flag, 'fim_changed')
                    msg      = f"FIM [{flag}] {'dir' if is_dir else 'file'}: {path}"
                    entry = {
                        'timestamp':     datetime.now(timezone.utc).isoformat(),
                        'level':         severity,
                        'source':        'fim_realtime',
                        'message':       msg,
                        'raw':           msg,
                        'parsed_fields': {
                            'event_type': etype,
                            'file_path':  path,
                            'flags':      [flag],
                            'is_dir':     is_dir,
                        },
                    }
                    try:
                        from queue import Full
                        queue_ref.put_nowait(entry)
                    except Full:
                        pass

                def on_created(self, e):   self._emit('CREATE',      e.src_path, e.is_directory)
                def on_modified(self, e):  self._emit('MODIFY',      e.src_path, e.is_directory)
                def on_deleted(self, e):   self._emit('DELETE',      e.src_path, e.is_directory)
                def on_moved(self, e):     self._emit('MOVED_FROM',  e.src_path, e.is_directory)

            observer = Observer()
            dirs_watched = set()
            for path in self._paths:
                path = os.path.realpath(path)
                watch_dir = path if os.path.isdir(path) else os.path.dirname(path)
                if watch_dir not in dirs_watched and os.path.isdir(watch_dir):
                    observer.schedule(_Handler(), watch_dir, recursive=False)
                    dirs_watched.add(watch_dir)

            if not dirs_watched:
                return False

            observer.start()
            self._watchdog_observer = observer
            self._thread = observer

            import sys as _sys
            platform_name = 'Windows (ReadDirectoryChangesW)' if _sys.platform == 'win32' else 'macOS (FSEvents)'
            logger.info(f"FIM-RT: {platform_name} watching {len(dirs_watched)} dir(s)")
            return True

        except ImportError:
            logger.warning("FIM-RT: watchdog not installed — real-time FIM disabled on Windows/macOS")
            logger.warning("FIM-RT: install with:  pip install watchdog")
            return False
        except Exception as e:
            logger.warning(f"FIM-RT: watchdog init failed: {e}")
            return False

    def _start_inotify(self) -> bool:
        """Linux: use inotify via ctypes."""
        if os.name != 'posix':
            return False
        try:
            self._ino = _Inotify()
        except Exception as e:
            logger.warning(f"FIM-RT: cannot init inotify: {e}")
            return False

        for path in self._paths:
            self._register(path)

        if not self._watches:
            self._ino.close()
            return False

        self._thread = threading.Thread(
            target=self._loop, name='fim-inotify', daemon=True
        )
        self._thread.start()
        logger.info(f"FIM-RT: watching {len(self._watches)} dirs "
                    f"for {len(self._paths)} paths — inotify active")
        return True

    def stop(self):
        self._stop.set()
        if self._ino:
            self._ino.close()
        # Stop watchdog observer if used (Windows/macOS)
        observer = getattr(self, '_watchdog_observer', None)
        if observer:
            try:
                observer.stop()
                observer.join(timeout=3)
            except Exception:
                pass

    # ── registration ──────────────────────────────────────────────────────────

    def _register(self, path: str):
        if self._ino is None:
            return
        path = os.path.realpath(path)
        if os.path.isdir(path):
            watch_dir   = path
            file_filter = None
        elif os.path.isfile(path):
            watch_dir   = os.path.dirname(path) or '/'
            file_filter = os.path.basename(path)
        else:
            logger.debug(f"FIM-RT: path not found (skipped): {path}")
            return

        # Deduplicate: if directory already watched, just update filter
        for wd, w in self._watches.items():
            if w.dir_path == watch_dir:
                if file_filter and w.file_filter:
                    # Multiple files in same dir — clear filter to watch all
                    w.file_filter = None
                return

        try:
            wd = self._ino.add_watch(watch_dir, WATCH_MASK)
            self._watches[wd] = _Watch(watch_dir, file_filter)
            logger.debug(f"FIM-RT: wd={wd} dir={watch_dir} filter={file_filter}")
        except OSError as e:
            logger.warning(f"FIM-RT: cannot watch {watch_dir}: {e}")

    # ── event loop ────────────────────────────────────────────────────────────

    def _loop(self):
        fd = self._ino.fd
        while not self._stop.is_set():
            try:
                ready, _, _ = select.select([fd], [], [], 1.0)
                if not ready:
                    continue
                for wd, mask, cookie, name in self._ino.read_events():
                    self._dispatch(wd, mask, name)
            except OSError:
                break
            except Exception as e:
                if not self._stop.is_set():
                    logger.debug(f"FIM-RT loop error: {e}")

    def _dispatch(self, wd: int, mask: int, name: str):
        if mask & IN_IGNORED:
            return
        w = self._watches.get(wd)
        if not w:
            return

        full_path = os.path.join(w.dir_path, name) if name else w.dir_path

        # Filter to specific file if set
        if w.file_filter and name and name != w.file_filter:
            return

        flags = [lbl for bit, lbl in _FLAG_NAMES.items() if mask & bit]
        if not flags:
            return

        primary  = flags[0]
        severity = _SEVERITY.get(primary, 'WARNING')
        etype    = _EVENT_TYPE.get(primary, 'fim_changed')
        is_dir   = bool(mask & IN_ISDIR)

        msg = f"FIM [{primary}] {'dir' if is_dir else 'file'}: {full_path}"

        entry = {
            'timestamp':     datetime.now(timezone.utc).isoformat(),
            'level':         severity,
            'source':        'fim_realtime',
            'message':       msg,
            'raw':           msg,
            'parsed_fields': {
                'event_type': etype,
                'file_path':  full_path,
                'flags':      flags,
                'is_dir':     is_dir,
                'watch_dir':  w.dir_path,
                'inotify_mask': mask,
            },
        }

        try:
            self._queue.put_nowait(entry)
        except Full:
            logger.warning("FIM-RT: event queue full — dropping event")
