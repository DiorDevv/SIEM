"""
Central data path resolver for all collector state files.
Uses SIEM_DATA_DIR env var (set by agent.py on startup) so that
Docker volume mounts work correctly without changing each collector.
"""
import os

_COLLECTOR_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_DATA  = os.path.join(_COLLECTOR_DIR, '..')


def data_path(filename: str) -> str:
    """Return absolute path to a state file inside the data directory."""
    base = os.environ.get('SIEM_DATA_DIR') or _DEFAULT_DATA
    return os.path.join(base, filename)
