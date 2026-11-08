"""
CyberGuard AI — Windows Collector Service Wrapper
============================================================================

Wraps the collector as a Windows Service so it runs continuously in the
background, starts on boot, and can be controlled via the standard
Service Control Manager (SCM) or ``sc start`` / ``sc stop`` commands.

Why a Service (not a scheduled task / not a plain process)
----------------------------------------------------------
A Windows Service:

    - Starts automatically at boot — no user login required
    - Runs as LocalSystem — has privileges to read the Security event log
    - Survives user logoffs and terminal disconnects
    - Managed by the OS — auto-restart on crash (if configured)
    - Managed by IT — GPOs, monitoring, standard tooling all work
    - Visible in ``services.msc`` — operators know where to find it

A scheduled task or a console process would fail at least one of these.

How the service works
---------------------
The SCM launches ``pythonservice.exe`` (from pywin32), which imports
this module and calls ``win32serviceutil.HandleCommandLine``. That
dispatches to one of our service methods:

    SvcDoRun         Called when the service starts. Runs the collector
                     until ``SvcStop`` is called. This is the primary
                     entry point.
    SvcStop          Called when the service is stopped. Sets the stop
                     event, waits for the collector to finish, returns.

The service delegates to ``main.main(["run"])`` — the exact same code
path as ``python main.py run``. The service is just a launcher; the
actual logic lives in ``main.py``. This keeps both invocation modes
consistent and testable.

Installation and control
------------------------
This file is not run directly for install/uninstall — that's
``install_service.ps1``. But the pywin32 standard commands still work:

    python service.py install
    python service.py start
    python service.py stop
    python service.py remove

The PowerShell installer wraps these with proper ACL setup and error
handling.

LocalSystem account
-------------------
The service must run as LocalSystem (or another account with the
"Manage auditing and security log" privilege) to read the Security
event log. The installer sets this. If run as a regular user, the
Security channel is inaccessible — the collector starts but logs a
warning and only reads System and Application.

Interaction with pywin32's event log
------------------------------------
pywin32 registers the service with the SCM, which can write to the
Windows Event Log. We also write to the Event Log via
``win32serviceutil.ReportEvent`` for critical lifecycle events
(start, stop, fatal error). This makes the service visible in
``Event Viewer → Windows Logs → Application`` for IT monitoring.

We do NOT write every log line to the Windows Event Log — that would
flood it. Only high-level lifecycle events.

Usage
-----
    # Install (must be Administrator):
    python service.py install

    # Start:
    python service.py start

    # Stop:
    python service.py stop

    # Uninstall:
    python service.py remove

    # Or use the PowerShell wrapper (recommended):
    .\install_service.ps1 -Action Install
    .\install_service.ps1 -Action Start
    .\install_service.ps1 -Action Status

Note: import fails gracefully on non-Windows so the file doesn't break
CI/lint on Linux dev machines.
"""

from __future__ import annotations

import logging
import sys
import threading
from pathlib import Path


logger = logging.getLogger(__name__)


# ============================================================================
# PLATFORM GUARD
# ============================================================================
# Everything below requires Windows + pywin32. If we're on Linux (dev,
# CI, lint), this module is a stub — importing it is safe but calling
# `run_service()` raises a clear error.

_IS_WINDOWS = sys.platform == "win32"

if _IS_WINDOWS:
    try:
        import pywintypes  # noqa: F401
        import win32event
        import win32service
        import win32serviceutil
        import servicemanager
        _PYWIN32_AVAILABLE = True
    except ImportError:
        _PYWIN32_AVAILABLE = False
else:
    _PYWIN32_AVAILABLE = False


# ============================================================================
# SERVICE IMPLEMENTATION
# ============================================================================
# Only defined when the platform supports it. The class below inherits
# from pywin32's ServiceFramework, so it can only be created on Windows
# with pywin32 installed.

if _IS_WINDOWS and _PYWIN32_AVAILABLE:

    class CyberGuardCollectorService(win32serviceutil.ServiceFramework):
        """
        Windows Service that runs the CyberGuard collector.

        pywin32's ServiceFramework handles SCM interaction; this class
        overrides ``SvcRun`` / ``SvcStop`` / ``SvcOtherEx`` to control
        the collector.
        """

        #: Internal SCM name (what shows in ``sc query`` and services.msc)
        _svc_name_ = "CyberGuardCollector"

        #: Display name in services.msc
        _svc_display_name_ = "CyberGuard AI Collector"

        #: Description shown in services.msc
        _svc_description_ = (
            "Monitors Windows Event Logs and streams security events to "
            "the CyberGuard AI platform. Managed by the CyberGuard "
            "installer."
        )

        #: Whether the service requires admin credentials to be set.
        #: The installer configures the account.
        _svc_deps_ = None

        def __init__(self, args) -> None:
            super().__init__(args)

            # SCM event handle: signaled when the service should stop.
            # pywin32 provides this; ``SvcStop`` is called by SCM, which
            # waits for ``SvcRun`` to return. We don't need our own event
            # — ``main.main()`` handles Ctrl+C/SIGTERM internally, and we
            # interrupt it via ``_request_stop``.
            self._stop_event = threading.Event()

            # The thread running the collector. ``SvcStop`` waits for it.
            self._collector_thread: threading.Thread | None = None

        # ── Lifecycle hooks ────────────────────────────────────────────

        def SvcStop(self) -> None:
            """
            Called by SCM when the service is asked to stop.

            Signals the collector to shut down gracefully, then
            reports status to SCM. SCM will not actually stop the
            process until ``SvcRun`` returns.
            """
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            logger.info("Service stop requested — signaling collector")
            self._stop_event.set()

            # Give the collector a bounded time to shut down. If it
            # takes longer than this, SCM will kill it.
            if self._collector_thread is not None:
                self._collector_thread.join(timeout=30.0)
                if self._collector_thread.is_alive():
                    logger.warning(
                        "Collector did not stop within 30s — SCM may "
                        "terminate the process"
                    )

        def SvcShutdown(self) -> None:
            """
            Called when the OS is shutting down. Same as SvcStop but
            gives the collector less time.
            """
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            logger.info("System shutdown — signaling collector")
            self._stop_event.set()
            if self._collector_thread is not None:
                self._collector_thread.join(timeout=15.0)

        def SvcRun(self) -> None:
            """
            Called when the service is started. Runs the collector
            until ``SvcStop`` signals it to stop.
            """
            try:
                self.ReportServiceStatus(win32service.SERVICE_START_PENDING)

                logger.info("Service starting — launching collector")
                self._write_event_log(
                    win32serviceutil.EVENTLOG_INFORMATION_TYPE,
                    msg="CyberGuard Collector service starting",
                )

                # Run the collector in a thread so SvcRun can return
                # immediately after starting it. This lets SCM handle
                # status transitions promptly.
                self._collector_thread = threading.Thread(
                    target=self._run_collector,
                    name="cyberguard-collector-main",
                    daemon=False,
                )
                self._collector_thread.start()

                self.ReportServiceStatus(win32service.SERVICE_RUNNING)
                logger.info("Service running")

                # Block SCM's SvcRun until the collector finishes.
                # The collector exits when the stop_event is set (via
                # SvcStop) OR when the collector decides to exit itself
                # (e.g. credential revoked permanently).
                self._collector_thread.join()

                logger.info("Collector finished — service exiting SvcRun")
                self._write_event_log(
                    win32serviceutil.EVENTLOG_INFORMATION_TYPE,
                    msg="CyberGuard Collector service stopped cleanly",
                )

            except Exception as exc:  # noqa: BLE001
                logger.exception("Unhandled exception in service SvcRun")
                self._write_event_log(
                    win32serviceutil.EVENTLOG_ERROR_TYPE,
                    msg=f"CyberGuard Collector service crashed: {exc}",
                )
                raise
            finally:
                self.ReportServiceStatus(win32service.SERVICE_STOPPED)

        # ── Internal ───────────────────────────────────────────────────

        def _run_collector(self) -> None:
            """
            Thread body that runs the actual collector.

            Delegates to ``main.main(["run"])``. When that returns
            (either because of stop_event or because of an internal
            fatal error), the thread ends and SvcRun unblocks.
            """
            try:
                from main import main as collector_main
                exit_code = collector_main(["run"])
                if exit_code != 0:
                    logger.warning(
                        "Collector exited with non-zero code",
                        extra={"exit_code": exit_code},
                    )
                    self._write_event_log(
                        win32serviceutil.EVENTLOG_WARNING_TYPE,
                        msg=(
                            f"CyberGuard Collector exited with code "
                            f"{exit_code} — investigate logs at "
                            f"%PROGRAMDATA%\\CyberGuard\\logs\\"
                        ),
                    )
            except Exception as exc:  # noqa: BLE001
                logger.exception("Collector crashed in service thread")
                self._write_event_log(
                    win32serviceutil.EVENTLOG_ERROR_TYPE,
                    msg=f"CyberGuard Collector crashed: {exc}",
                )

        def _write_event_log(self, event_type: int, msg: str) -> None:
            """
            Write to the Windows Event Log (Application log) for IT
            visibility. Only used for lifecycle events — not per-event
            logging (that would flood the log).
            """
            try:
                win32serviceutil.ReportEvent(
                    self._svc_name_,
                    event_id=1,
                    eventType=event_type,
                    strings=[msg],
                )
            except Exception:  # noqa: BLE001
                # Never let event-log failure kill the service
                logger.exception("Failed to write Windows Event Log entry")


# ============================================================================
# PUBLIC ENTRY POINT
# ============================================================================

def run_service(argv: list[str] | None = None) -> None:
    """
    Dispatch to pywin32's command-line handler.

    Called from the command line as:
        python service.py install
        python service.py start
        python service.py stop
        python service.py remove
        python service.py debug

    Or from install_service.ps1, which invokes the same commands with
    proper elevation.
    """
    if not _IS_WINDOWS:
        raise RuntimeError(
            "service.py requires Windows. Current platform: "
            f"{sys.platform}. The collector service cannot run on "
            "non-Windows systems."
        )

    if not _PYWIN32_AVAILABLE:
        raise RuntimeError(
            "pywin32 is required to run the collector as a Windows "
            "service. Install it with: pip install pywin32"
        )

    win32serviceutil.HandleCommandLine(
        CyberGuardCollectorService,
        argv=argv,
    )


# ============================================================================
# COMMAND-LINE ENTRY (if executed directly)
# ============================================================================

if __name__ == "__main__":
    if not _IS_WINDOWS:
        print(
            "service.py can only be run on Windows.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not _PYWIN32_AVAILABLE:
        print(
            "pywin32 is not installed. Run: pip install pywin32",
            file=sys.stderr,
        )
        sys.exit(1)

    run_service()