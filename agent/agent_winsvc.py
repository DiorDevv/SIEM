"""
Windows Service wrapper for SecureWatch SIEM Agent.

Uses pywin32 so the SCM (Service Control Manager) can properly
start, stop, and restart the agent process.

Usage (elevated PowerShell, from install dir):
    python agent_winsvc.py --startup auto install
    python agent_winsvc.py start
    python agent_winsvc.py stop
    python agent_winsvc.py remove
"""
import os
import sys
import threading

# Must be set before importing agent so DATA_DIR is picked up at module level
_DIR = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("DATA_DIR", _DIR)
os.chdir(_DIR)
sys.path.insert(0, _DIR)

# Ensure pywin32 DLLs are findable when SCM starts this in a restricted environment.
# Add pywin32_system32 and the base Python directory to DLL search path.
def _fix_pywin32_path() -> None:
    import site
    for sp in site.getsitepackages():
        dll_dir = os.path.join(sp, "pywin32_system32")
        if os.path.isdir(dll_dir):
            os.add_dll_directory(dll_dir)
            break
    base = getattr(sys, "base_prefix", sys.prefix)
    if os.path.isdir(base):
        try:
            os.add_dll_directory(base)
        except Exception:
            pass

try:
    _fix_pywin32_path()
except Exception:
    pass

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
except ImportError:
    print("pywin32 is required. Run:  pip install pywin32")
    sys.exit(1)


class SIEMAgentService(win32serviceutil.ServiceFramework):
    _svc_name_         = "SIEMAgent"
    _svc_display_name_ = "SecureWatch SIEM Agent"
    _svc_description_  = "SecureWatch security monitoring agent"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self._stop_event = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        # Signal agent main loop to exit gracefully
        try:
            import agent as _agent
            _agent._shutdown.set()
        except Exception:
            pass
        win32event.SetEvent(self._stop_event)

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        import agent as _agent
        t = threading.Thread(target=_agent.main, daemon=True, name="agent-main")
        t.start()
        # Block until SCM sends STOP
        win32event.WaitForSingleObject(self._stop_event, win32event.INFINITE)
        t.join(timeout=15)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Called by SCM at service start
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(SIEMAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(SIEMAgentService)
