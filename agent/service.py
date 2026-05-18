"""Windows Service wrapper pentru agent VulnWatch (mode LocalSystem).

Service-ul invocă `core.daemon_loop` pe un thread, expune un named pipe pentru
control de la GUI (user session), și se înregistrează în Service Control
Manager. Activitate pre/post-stop tratată prin servicemanager events.
"""
from __future__ import annotations

import sys
import threading
import time
from typing import Optional

# pywin32 — disponibil doar pe Windows. Restul codului trebuie să degradeze
# gracefully când lipsește (dev pe non-Windows).
try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil
    _PYWIN32_AVAILABLE = True
except ImportError:
    _PYWIN32_AVAILABLE = False

SERVICE_NAME = "VulnWatchSvc"
SERVICE_DISPLAY_NAME = "VulnWatch Agent Service"
SERVICE_DESCRIPTION = ("Background scanner service for VulnWatch platform. "
                       "Runs heartbeat, scan jobs, and nmap-based deep scans.")


if _PYWIN32_AVAILABLE:
    class VulnWatchService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            self._stop_flag = threading.Event()
            self._daemon_thread: Optional[threading.Thread] = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._stop_flag.set()
            win32event.SetEvent(self.stop_event)

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            self._main()

        def _main(self) -> None:
            """Logica principală: pornește daemon_loop pe thread + așteaptă stop."""
            # Import lazy ca să nu crashăm pe non-Windows
            from . import core

            try:
                api_base, device_uid, device_token = core.get_enrollment()
            except RuntimeError:
                servicemanager.LogErrorMsg(
                    "VulnWatchSvc: agent neînrolat. Service se oprește."
                )
                return

            def daemon_target():
                core.daemon_loop(
                    api_base, device_uid, device_token,
                    poll_interval=3,
                    log=lambda msg, sev: servicemanager.LogInfoMsg(f"[{sev}] {msg}"),
                    should_stop=self._stop_flag.is_set,
                )

            self._daemon_thread = threading.Thread(
                target=daemon_target, daemon=True, name="vulnwatch-daemon",
            )
            self._daemon_thread.start()

            # Așteaptă stop event
            try:
                win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
                self._daemon_thread.join(timeout=5.0)
            except Exception as e:
                servicemanager.LogErrorMsg(f"VulnWatchSvc crash: {e}")
                raise
else:
    # Stub pentru dev pe non-Windows
    class VulnWatchService:
        pass


def install_service() -> int:
    """Înregistrează serviciul în SCM. Trebuie rulat sub UAC admin."""
    if not _PYWIN32_AVAILABLE:
        print("pywin32 indisponibil — Service mode necesită Windows.")
        return 1
    exe_path = sys.executable
    # Construim args: când SCM pornește serviciul, va apela exe-ul cu acești args
    win32serviceutil.InstallService(
        pythonClassString="agent.service.VulnWatchService",
        serviceName=SERVICE_NAME,
        displayName=SERVICE_DISPLAY_NAME,
        description=SERVICE_DESCRIPTION,
        startType=win32service.SERVICE_AUTO_START,
        exeName=exe_path,
        exeArgs="--service",
    )
    # Start imediat
    win32serviceutil.StartService(SERVICE_NAME)
    return 0


def uninstall_service() -> int:
    """Oprește + dezinstalează serviciul. Trebuie rulat sub UAC admin."""
    if not _PYWIN32_AVAILABLE:
        return 1
    try:
        win32serviceutil.StopService(SERVICE_NAME)
    except Exception:
        pass  # poate nu rula
    win32serviceutil.RemoveService(SERVICE_NAME)
    return 0


def is_service_installed() -> bool:
    """Returnează True dacă serviciul e înregistrat în SCM."""
    if not _PYWIN32_AVAILABLE:
        return False
    try:
        import pywintypes
        try:
            win32serviceutil.QueryServiceStatus(SERVICE_NAME)
            return True
        except pywintypes.error:
            return False
    except ImportError:
        return False


def is_service_running() -> bool:
    if not _PYWIN32_AVAILABLE:
        return False
    try:
        import pywintypes
        try:
            status = win32serviceutil.QueryServiceStatus(SERVICE_NAME)
            return status[1] == win32service.SERVICE_RUNNING
        except pywintypes.error:
            return False
    except ImportError:
        return False


def run_as_service() -> int:
    """Entry point când exe-ul e lansat de SCM cu --service flag."""
    if not _PYWIN32_AVAILABLE:
        print("--service necesită Windows + pywin32")
        return 1
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(VulnWatchService)
    servicemanager.StartServiceCtrlDispatcher()
    return 0
