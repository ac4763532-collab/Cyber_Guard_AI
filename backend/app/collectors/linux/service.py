"""
CyberGuard AI — Linux Collector systemd Service Definition
============================================================================

Generates, installs, and manages the systemd unit for the collector.

Why this is a *generator* and not a service class
-------------------------------------------------
The Windows collector uses pywin32's ``ServiceFramework`` — a Python
class the SCM instantiates and dispatches lifecycle callbacks to.

systemd works differently. It reads a *unit file* from
``/etc/systemd/system/`` and:

    - Executes ``ExecStart`` as a subprocess
    - Sends SIGTERM on stop, waits ``TimeoutStopSec``, sends SIGKILL
    - Captures stdout/stderr into the journal automatically
    - Restarts on failure per ``Restart=``
    - Applies resource limits per ``MemoryMax=`` / ``CPUQuota=``
    - Applies sandboxing per the ``Protect*`` / ``Restrict*`` directives

There is no Python callback in the systemd model. The service *is*
the unit file. So this module's job is to render and write that
file, and then let ``systemctl`` do the rest.

Why not ship a static .service file?
------------------------------------
Because several directives vary per installation:

    - ``ExecStart`` needs the actual python path (``/usr/bin/python3``
      vs. ``/opt/cyberguard/venv/bin/python``)
    - ``WorkingDirectory`` needs the actual collector directory
    - ``ReadWritePaths`` needs the actual state + log + config dirs
      (which can differ if ``STATE_DIR`` was overridden)

Templating at install time means the unit is always correct, not
"usually right on this distro but wrong on that one."

The unit file
-------------
Full template lives in ``_UNIT_TEMPLATE`` below. Highlights:

    Type=simple
        main.py runs in the foreground — no forking.

    User=root
        Required to read /var/log/secure, /var/log/audit/audit.log,
        and the Security-relevant journald entries on hardened
        systems where non-root users have reduced visibility.
        (Same reasoning as LocalSystem on Windows.)

    Restart=on-failure
        Restart if exit code != 0. A clean exit (0) means the
        operator stopped it deliberately.

    RestartSec=10
        Wait 10s between restart attempts — enough to let DB locks
        release, not so long that recovery feels broken.

    StartLimitBurst=5 / StartLimitIntervalSec=300
        After 5 restarts within 5 minutes, give up. Something is
        fundamentally broken and looping won't help — systemd
        marks the unit failed, alerts the operator.

    TimeoutStopSec=30
        Matches main.py's internal 15s+15s join window. systemd
        sends SIGTERM, waits up to 30s, then SIGKILL.

    StandardOutput=journal / StandardError=journal
        Logs go to journald — no need for a separate log shipping
        mechanism. ``journalctl -u cyberguard-collector`` works.

    ProtectSystem=strict + ReadWritePaths=...
        /usr, /boot, /etc are read-only to the process. The three
        directories the collector legitimately writes to are the
        only writable exceptions. This contains the blast radius
        if the collector is ever compromised.

    NoNewPrivileges=true
        Prevents the process (and any children) from gaining new
        privileges via setuid/setcap. Defense in depth.

CLI
---
    python3 service.py print         # dump unit to stdout
    python3 service.py write         # write to /etc/systemd/system/
    python3 service.py uninstall     # remove the unit file
    python3 service.py status        # show installed unit if present

The ``write`` command requires root. ``print`` does not.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


# ============================================================================
# CONSTANTS
# ============================================================================

UNIT_NAME = "cyberguard-collector.service"
DEFAULT_UNIT_PATH = Path("/etc/systemd/system") / UNIT_NAME

#: Directories the collector writes to. Templated into ``ReadWritePaths=``.
#: These must be writable even under ``ProtectSystem=strict``.
_WRITABLE_DIRS = (
    "/etc/cyberguard/collector",       # config.json, cursor persistence
    "/var/lib/cyberguard/collector",   # queue.db, credential.enc, fernet.key
    "/var/log/cyberguard",             # collector.log
)


# ============================================================================
# UNIT TEMPLATE
# ============================================================================
# Using ``.format()`` with named placeholders (safe because the
# substituted values are paths we control, not user input).

_UNIT_TEMPLATE = """\
[Unit]
Description=CyberGuard AI Collector
Documentation=https://github.com/cyberguard/collector
After=network-online.target
Wants=network-online.target
# Do not start before the machine has a working clock — journald
# cursors and event timestamps need a valid UTC baseline.
After=time-sync.target
Wants=time-sync.target

[Service]
Type=simple

# The actual command — templated at install time
WorkingDirectory={working_directory}
ExecStart={python_executable} {main_script} run

# Restart policy
Restart=on-failure
RestartSec=10
StartLimitBurst=5
StartLimitIntervalSec=300

# Graceful shutdown window (main.py finishes in <30s normally)
TimeoutStopSec=30
KillMode=mixed
KillSignal=SIGTERM

# Logging — journald captures both streams
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cyberguard-collector

# Environment
Environment="PYTHONUNBUFFERED=1"
Environment="PYTHONIOENCODING=utf-8"
# Optional .env overrides — the leading `-` means "don't fail if missing"
EnvironmentFile=-/etc/cyberguard/collector/.env

# Privileges — root required to read the Security-relevant journald
# entries and /var/log/secure on hardened systems.
User=root
Group=root

# Sandboxing — read-only filesystem except for the three directories
# we legitimately write to. Contains the blast radius if the collector
# is compromised.
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
NoNewPrivileges=true

# Networking — collector needs outbound HTTPS to the backend only.
# AF_UNIX is required for journalctl subprocess communication.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# Explicitly whitelist the writable paths (systemd requires both
# ProtectSystem=strict AND explicit ReadWritePaths for exceptions)
ReadWritePaths={writable_paths}

# Resource limits — 512 MB is generous for log buffering; a runaway
# collector gets OOM-killed by the kernel rather than starving the host.
MemoryMax=512M
TasksMax=256

[Install]
WantedBy=multi-user.target
"""


# ============================================================================
# TEMPLATE RENDERING
# ============================================================================

def _detect_python_executable() -> str:
    """
    Return the absolute path to the python3 running this script.

    systemd does not inherit the invoking user's PATH. ``ExecStart``
    must be an absolute path. ``sys.executable`` gives us exactly the
    interpreter that ran ``python3 service.py`` — which is the correct
    one (whatever virtualenv or system python the operator used).
    """
    exe = sys.executable
    if not exe or not Path(exe).exists():
        # Fallback — but this shouldn't happen for a running interpreter
        return "/usr/bin/python3"
    return exe


def _detect_main_script() -> Path:
    """
    Return the absolute path to main.py.

    Assumed to live in the same directory as this service.py.
    """
    here = Path(__file__).resolve().parent
    return here / "main.py"


def render_unit(
    *,
    working_directory: Path | None = None,
    python_executable: str | None = None,
    main_script: Path | None = None,
) -> str:
    """
    Render the systemd unit file with all paths filled in.

    Parameters can be overridden for testing, but by default they
    resolve to the *actual* paths on this system.
    """
    if working_directory is None:
        working_directory = Path(__file__).resolve().parent
    if python_executable is None:
        python_executable = _detect_python_executable()
    if main_script is None:
        main_script = _detect_main_script()

    if not main_script.exists():
        raise FileNotFoundError(
            f"main.py not found at {main_script}. "
            f"service.py must live in the same directory as main.py."
        )

    return _UNIT_TEMPLATE.format(
        working_directory=str(working_directory),
        python_executable=str(python_executable),
        main_script=str(main_script),
        writable_paths=" ".join(_WRITABLE_DIRS),
    )


# ============================================================================
# PLATFORM CHECKS
# ============================================================================

def _require_linux() -> None:
    """Raise if we're not on Linux."""
    if sys.platform != "linux":
        raise RuntimeError(
            "service.py on the Linux collector requires Linux. "
            f"Current platform: {sys.platform}. "
            "On Windows, use the Windows collector's service.py."
        )


def _require_root() -> None:
    """Raise if we're not running as root (required for install)."""
    try:
        if os.geteuid() != 0:
            raise RuntimeError(
                "This command must be run as root. "
                "Try: sudo python3 service.py <command>"
            )
    except AttributeError as exc:
        raise RuntimeError(
            "Cannot check UID on this platform (unusual). "
            "Run with sudo."
        ) from exc


def _require_systemd() -> None:
    """Raise if systemd's ``systemctl`` is not available."""
    import shutil
    if shutil.which("systemctl") is None:
        raise RuntimeError(
            "systemctl not found — this system does not appear to "
            "run systemd. The CyberGuard Linux collector requires "
            "systemd. For non-systemd init systems (OpenRC, runit, "
            "s6), use `python3 main.py run` directly under your "
            "init system's process supervisor."
        )


# ============================================================================
# CLI COMMANDS
# ============================================================================

def _cmd_print(args: argparse.Namespace) -> int:  # noqa: ARG001
    """Dump the unit file to stdout (no filesystem writes, no root)."""
    _require_linux()
    try:
        unit_content = render_unit()
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(unit_content)
    return 0


def _cmd_write(args: argparse.Namespace) -> int:
    """Write the unit file to /etc/systemd/system/cyberguard-collector.service."""
    _require_linux()
    _require_root()
    _require_systemd()

    try:
        unit_content = render_unit()
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    unit_path = Path(args.path) if args.path else DEFAULT_UNIT_PATH

    # Back up an existing unit before overwriting
    if unit_path.exists():
        backup = unit_path.with_suffix(unit_path.suffix + ".bak")
        try:
            unit_path.rename(backup)
            print(f"  Backed up existing unit to {backup}")
        except OSError as exc:
            print(
                f"Warning: could not back up existing unit: {exc}",
                file=sys.stderr,
            )

    # Write atomically
    tmp = unit_path.with_suffix(unit_path.suffix + ".tmp")
    try:
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(unit_content, encoding="utf-8")
        tmp.replace(unit_path)
    except OSError as exc:
        print(f"Error: cannot write {unit_path}: {exc}", file=sys.stderr)
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return 1

    print(f"  Wrote systemd unit to {unit_path}")
    print()
    print("Next steps (usually run by install_service.sh):")
    print("  systemctl daemon-reload")
    print(f"  systemctl enable {UNIT_NAME}")
    print(f"  systemctl start {UNIT_NAME}")
    return 0


def _cmd_uninstall(args: argparse.Namespace) -> int:  # noqa: ARG001
    """Remove the unit file (does NOT stop the service — see install_service.sh)."""
    _require_linux()
    _require_root()

    unit_path = DEFAULT_UNIT_PATH
    if not unit_path.exists():
        print(f"  Unit file {unit_path} not present — nothing to remove.")
        return 0

    try:
        unit_path.unlink()
        print(f"  Removed {unit_path}")
    except OSError as exc:
        print(f"Error: cannot remove {unit_path}: {exc}", file=sys.stderr)
        return 1

    print("  Run `systemctl daemon-reload` to apply the removal.")
    return 0


def _cmd_status(args: argparse.Namespace) -> int:  # noqa: ARG001
    """Show the installed unit's content and systemctl status summary."""
    _require_linux()

    if not DEFAULT_UNIT_PATH.exists():
        print(f"  Unit {UNIT_NAME} is not installed.")
        print(f"  Install with: sudo ./install_service.sh install")
        return 1

    print(f"  Unit file: {DEFAULT_UNIT_PATH}")
    print("=" * 60)
    try:
        print(DEFAULT_UNIT_PATH.read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"Error reading unit file: {exc}", file=sys.stderr)
        return 1
    return 0


# ============================================================================
# ARGUMENT PARSER
# ============================================================================

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="service.py",
        description=(
            "CyberGuard AI Linux Collector — systemd unit management. "
            "For install/start/stop operations, use install_service.sh."
        ),
    )
    sub = parser.add_subparsers(
        dest="command", required=True, metavar="<command>",
    )

    p = sub.add_parser(
        "print",
        help="Render the systemd unit file to stdout (no root required).",
    )
    p.set_defaults(func=_cmd_print)

    p = sub.add_parser(
        "write",
        help="Write the unit file to /etc/systemd/system/ (requires root).",
    )
    p.add_argument(
        "--path",
        default=None,
        help=(
            f"Target path (default: {DEFAULT_UNIT_PATH}). "
            f"Useful for testing or non-standard installs."
        ),
    )
    p.set_defaults(func=_cmd_write)

    p = sub.add_parser(
        "uninstall",
        help="Remove the installed unit file (requires root).",
    )
    p.set_defaults(func=_cmd_uninstall)

    p = sub.add_parser(
        "status",
        help="Print the installed unit file's content.",
    )
    p.set_defaults(func=_cmd_status)

    return parser


# ============================================================================
# MAIN
# ============================================================================

def main(argv: list[str] | None = None) -> int:
    """Parse args and dispatch to the requested command."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        return args.func(args)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 1
    except Exception:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
"""
CyberGuard AI — Linux Collector systemd Service Definition
============================================================================

Generates, installs, and manages the systemd unit for the collector.

Why this is a *generator* and not a service class
-------------------------------------------------
The Windows collector uses pywin32's ``ServiceFramework`` — a Python
class the SCM instantiates and dispatches lifecycle callbacks to.

systemd works differently. It reads a *unit file* from
``/etc/systemd/system/`` and:

    - Executes ``ExecStart`` as a subprocess
    - Sends SIGTERM on stop, waits ``TimeoutStopSec``, sends SIGKILL
    - Captures stdout/stderr into the journal automatically
    - Restarts on failure per ``Restart=``
    - Applies resource limits per ``MemoryMax=`` / ``CPUQuota=``
    - Applies sandboxing per the ``Protect*`` / ``Restrict*`` directives

There is no Python callback in the systemd model. The service *is*
the unit file. So this module's job is to render and write that
file, and then let ``systemctl`` do the rest.

Why not ship a static .service file?
------------------------------------
Because several directives vary per installation:

    - ``ExecStart`` needs the actual python path (``/usr/bin/python3``
      vs. ``/opt/cyberguard/venv/bin/python``)
    - ``WorkingDirectory`` needs the actual collector directory
    - ``ReadWritePaths`` needs the actual state + log + config dirs
      (which can differ if ``STATE_DIR`` was overridden)

Templating at install time means the unit is always correct, not
"usually right on this distro but wrong on that one."

The unit file
-------------
Full template lives in ``_UNIT_TEMPLATE`` below. Highlights:

    Type=simple
        main.py runs in the foreground — no forking.

    User=root
        Required to read /var/log/secure, /var/log/audit/audit.log,
        and the Security-relevant journald entries on hardened
        systems where non-root users have reduced visibility.
        (Same reasoning as LocalSystem on Windows.)

    Restart=on-failure
        Restart if exit code != 0. A clean exit (0) means the
        operator stopped it deliberately.

    RestartSec=10
        Wait 10s between restart attempts — enough to let DB locks
        release, not so long that recovery feels broken.

    StartLimitBurst=5 / StartLimitIntervalSec=300
        After 5 restarts within 5 minutes, give up. Something is
        fundamentally broken and looping won't help — systemd
        marks the unit failed, alerts the operator.

    TimeoutStopSec=30
        Matches main.py's internal 15s+15s join window. systemd
        sends SIGTERM, waits up to 30s, then SIGKILL.

    StandardOutput=journal / StandardError=journal
        Logs go to journald — no need for a separate log shipping
        mechanism. ``journalctl -u cyberguard-collector`` works.

    ProtectSystem=strict + ReadWritePaths=...
        /usr, /boot, /etc are read-only to the process. The three
        directories the collector legitimately writes to are the
        only writable exceptions. This contains the blast radius
        if the collector is ever compromised.

    NoNewPrivileges=true
        Prevents the process (and any children) from gaining new
        privileges via setuid/setcap. Defense in depth.

CLI
---
    python3 service.py print         # dump unit to stdout
    python3 service.py write         # write to /etc/systemd/system/
    python3 service.py uninstall     # remove the unit file
    python3 service.py status        # show installed unit if present

The ``write`` command requires root. ``print`` does not.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


# ============================================================================
# CONSTANTS
# ============================================================================

UNIT_NAME = "cyberguard-collector.service"
DEFAULT_UNIT_PATH = Path("/etc/systemd/system") / UNIT_NAME

#: Directories the collector writes to. Templated into ``ReadWritePaths=``.
#: These must be writable even under ``ProtectSystem=strict``.
_WRITABLE_DIRS = (
    "/etc/cyberguard/collector",       # config.json, cursor persistence
    "/var/lib/cyberguard/collector",   # queue.db, credential.enc, fernet.key
    "/var/log/cyberguard",             # collector.log
)


# ============================================================================
# UNIT TEMPLATE
# ============================================================================
# Using ``.format()`` with named placeholders (safe because the
# substituted values are paths we control, not user input).

_UNIT_TEMPLATE = """\
[Unit]
Description=CyberGuard AI Collector
Documentation=https://github.com/cyberguard/collector
After=network-online.target
Wants=network-online.target
# Do not start before the machine has a working clock — journald
# cursors and event timestamps need a valid UTC baseline.
After=time-sync.target
Wants=time-sync.target

[Service]
Type=simple

# The actual command — templated at install time
WorkingDirectory={working_directory}
ExecStart={python_executable} {main_script} run

# Restart policy
Restart=on-failure
RestartSec=10
StartLimitBurst=5
StartLimitIntervalSec=300

# Graceful shutdown window (main.py finishes in <30s normally)
TimeoutStopSec=30
KillMode=mixed
KillSignal=SIGTERM

# Logging — journald captures both streams
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cyberguard-collector

# Environment
Environment="PYTHONUNBUFFERED=1"
Environment="PYTHONIOENCODING=utf-8"
# Optional .env overrides — the leading `-` means "don't fail if missing"
EnvironmentFile=-/etc/cyberguard/collector/.env

# Privileges — root required to read the Security-relevant journald
# entries and /var/log/secure on hardened systems.
User=root
Group=root

# Sandboxing — read-only filesystem except for the three directories
# we legitimately write to. Contains the blast radius if the collector
# is compromised.
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
NoNewPrivileges=true

# Networking — collector needs outbound HTTPS to the backend only.
# AF_UNIX is required for journalctl subprocess communication.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# Explicitly whitelist the writable paths (systemd requires both
# ProtectSystem=strict AND explicit ReadWritePaths for exceptions)
ReadWritePaths={writable_paths}

# Resource limits — 512 MB is generous for log buffering; a runaway
# collector gets OOM-killed by the kernel rather than starving the host.
MemoryMax=512M
TasksMax=256

[Install]
WantedBy=multi-user.target
"""


# ============================================================================
# TEMPLATE RENDERING
# ============================================================================

def _detect_python_executable() -> str:
    """
    Return the absolute path to the python3 running this script.

    systemd does not inherit the invoking user's PATH. ``ExecStart``
    must be an absolute path. ``sys.executable`` gives us exactly the
    interpreter that ran ``python3 service.py`` — which is the correct
    one (whatever virtualenv or system python the operator used).
    """
    exe = sys.executable
    if not exe or not Path(exe).exists():
        # Fallback — but this shouldn't happen for a running interpreter
        return "/usr/bin/python3"
    return exe


def _detect_main_script() -> Path:
    """
    Return the absolute path to main.py.

    Assumed to live in the same directory as this service.py.
    """
    here = Path(__file__).resolve().parent
    return here / "main.py"


def render_unit(
    *,
    working_directory: Path | None = None,
    python_executable: str | None = None,
    main_script: Path | None = None,
) -> str:
    """
    Render the systemd unit file with all paths filled in.

    Parameters can be overridden for testing, but by default they
    resolve to the *actual* paths on this system.
    """
    if working_directory is None:
        working_directory = Path(__file__).resolve().parent
    if python_executable is None:
        python_executable = _detect_python_executable()
    if main_script is None:
        main_script = _detect_main_script()

    if not main_script.exists():
        raise FileNotFoundError(
            f"main.py not found at {main_script}. "
            f"service.py must live in the same directory as main.py."
        )

    return _UNIT_TEMPLATE.format(
        working_directory=str(working_directory),
        python_executable=str(python_executable),
        main_script=str(main_script),
        writable_paths=" ".join(_WRITABLE_DIRS),
    )


# ============================================================================
# PLATFORM CHECKS
# ============================================================================

def _require_linux() -> None:
    """Raise if we're not on Linux."""
    if sys.platform != "linux":
        raise RuntimeError(
            "service.py on the Linux collector requires Linux. "
            f"Current platform: {sys.platform}. "
            "On Windows, use the Windows collector's service.py."
        )


def _require_root() -> None:
    """Raise if we're not running as root (required for install)."""
    try:
        if os.geteuid() != 0:
            raise RuntimeError(
                "This command must be run as root. "
                "Try: sudo python3 service.py <command>"
            )
    except AttributeError as exc:
        raise RuntimeError(
            "Cannot check UID on this platform (unusual). "
            "Run with sudo."
        ) from exc


def _require_systemd() -> None:
    """Raise if systemd's ``systemctl`` is not available."""
    import shutil
    if shutil.which("systemctl") is None:
        raise RuntimeError(
            "systemctl not found — this system does not appear to "
            "run systemd. The CyberGuard Linux collector requires "
            "systemd. For non-systemd init systems (OpenRC, runit, "
            "s6), use `python3 main.py run` directly under your "
            "init system's process supervisor."
        )


# ============================================================================
# CLI COMMANDS
# ============================================================================

def _cmd_print(args: argparse.Namespace) -> int:  # noqa: ARG001
    """Dump the unit file to stdout (no filesystem writes, no root)."""
    _require_linux()
    try:
        unit_content = render_unit()
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(unit_content)
    return 0


def _cmd_write(args: argparse.Namespace) -> int:
    """Write the unit file to /etc/systemd/system/cyberguard-collector.service."""
    _require_linux()
    _require_root()
    _require_systemd()

    try:
        unit_content = render_unit()
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    unit_path = Path(args.path) if args.path else DEFAULT_UNIT_PATH

    # Back up an existing unit before overwriting
    if unit_path.exists():
        backup = unit_path.with_suffix(unit_path.suffix + ".bak")
        try:
            unit_path.rename(backup)
            print(f"  Backed up existing unit to {backup}")
        except OSError as exc:
            print(
                f"Warning: could not back up existing unit: {exc}",
                file=sys.stderr,
            )

    # Write atomically
    tmp = unit_path.with_suffix(unit_path.suffix + ".tmp")
    try:
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(unit_content, encoding="utf-8")
        tmp.replace(unit_path)
    except OSError as exc:
        print(f"Error: cannot write {unit_path}: {exc}", file=sys.stderr)
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return 1

    print(f"  Wrote systemd unit to {unit_path}")
    print()
    print("Next steps (usually run by install_service.sh):")
    print("  systemctl daemon-reload")
    print(f"  systemctl enable {UNIT_NAME}")
    print(f"  systemctl start {UNIT_NAME}")
    return 0


def _cmd_uninstall(args: argparse.Namespace) -> int:  # noqa: ARG001
    """Remove the unit file (does NOT stop the service — see install_service.sh)."""
    _require_linux()
    _require_root()

    unit_path = DEFAULT_UNIT_PATH
    if not unit_path.exists():
        print(f"  Unit file {unit_path} not present — nothing to remove.")
        return 0

    try:
        unit_path.unlink()
        print(f"  Removed {unit_path}")
    except OSError as exc:
        print(f"Error: cannot remove {unit_path}: {exc}", file=sys.stderr)
        return 1

    print("  Run `systemctl daemon-reload` to apply the removal.")
    return 0


def _cmd_status(args: argparse.Namespace) -> int:  # noqa: ARG001
    """Show the installed unit's content and systemctl status summary."""
    _require_linux()

    if not DEFAULT_UNIT_PATH.exists():
        print(f"  Unit {UNIT_NAME} is not installed.")
        print(f"  Install with: sudo ./install_service.sh install")
        return 1

    print(f"  Unit file: {DEFAULT_UNIT_PATH}")
    print("=" * 60)
    try:
        print(DEFAULT_UNIT_PATH.read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"Error reading unit file: {exc}", file=sys.stderr)
        return 1
    return 0


# ============================================================================
# ARGUMENT PARSER
# ============================================================================

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="service.py",
        description=(
            "CyberGuard AI Linux Collector — systemd unit management. "
            "For install/start/stop operations, use install_service.sh."
        ),
    )
    sub = parser.add_subparsers(
        dest="command", required=True, metavar="<command>",
    )

    p = sub.add_parser(
        "print",
        help="Render the systemd unit file to stdout (no root required).",
    )
    p.set_defaults(func=_cmd_print)

    p = sub.add_parser(
        "write",
        help="Write the unit file to /etc/systemd/system/ (requires root).",
    )
    p.add_argument(
        "--path",
        default=None,
        help=(
            f"Target path (default: {DEFAULT_UNIT_PATH}). "
            f"Useful for testing or non-standard installs."
        ),
    )
    p.set_defaults(func=_cmd_write)

    p = sub.add_parser(
        "uninstall",
        help="Remove the installed unit file (requires root).",
    )
    p.set_defaults(func=_cmd_uninstall)

    p = sub.add_parser(
        "status",
        help="Print the installed unit file's content.",
    )
    p.set_defaults(func=_cmd_status)

    return parser


# ============================================================================
# MAIN
# ============================================================================

def main(argv: list[str] | None = None) -> int:
    """Parse args and dispatch to the requested command."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        return args.func(args)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 1
    except Exception:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())