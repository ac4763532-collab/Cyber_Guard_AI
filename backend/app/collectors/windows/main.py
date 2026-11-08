"""
CyberGuard AI — Windows Collector Main Entrypoint
============================================================================

The collector's CLI and orchestration layer. Ties together every module:

    config.py              → settings + collector_id
    credential_store.py    → DPAPI-encrypted credential
    api_client.py          → HTTP client
    event_queue.py         → SQLite durable queue
    event_log_reader.py    → Windows Event Log reader
    event_normalizer.py    → Windows → CyberGuard event shape
    event_sender.py        → Background send thread
    heartbeat_worker.py    → Background heartbeat thread

This file is the conductor. It parses CLI arguments, starts the
background threads, runs the reader loop in the main thread, and
coordinates graceful shutdown.

Commands
--------
    run                 Start the collector (this is the normal command)
    enroll <token>      Redeem an enrollment token, save credential
    status              Show current status (enrolled? backend reachable? queue size?)
    test-connection     Probe the backend /health endpoint
    clear-credential    Remove stored credential (forces re-enroll)
    version             Show collector version

Architecture when running
-------------------------
Three threads:

    Main thread          Reader loop — reads Windows event logs,
                         normalizes, enqueues.
    Sender thread        Pulls batches from queue, sends to backend.
    Heartbeat thread     Sends periodic heartbeats.

The main thread also monitors the heartbeat thread. If heartbeat
stops (credential revoked, backend permanently rejecting), the
collector shuts down gracefully — no point continuing to collect
events that will never be sent.

Ctrl+C handling
---------------
On Ctrl+C (or service stop from the SCM):

    1. ``stop_event`` is set.
    2. Reader loop checks the event and breaks.
    3. Sender and heartbeat threads check the event and break.
    4. Main thread joins all threads (with timeout).
    5. SQLite queue is closed cleanly.

Events still in the queue remain for next start — nothing is lost.

Graceful degradation
--------------------
If the backend is unreachable at startup:
    - Collector keeps running, buffering events in the queue.
    - Heartbeat fails but retries with backoff.
    - When the backend returns, everything drains normally.

If the credential is dead at startup:
    - Heartbeat fails permanently on first attempt.
    - The collector logs a clear "re-enroll" message and stops.
    - Operator runs ``main.py enroll <new-token>``.

Exit codes
----------
    0    Success
    1    Unexpected error
    2    Configuration error (missing/malformed)
    3    Not enrolled (need to run ``enroll``)
    4    Credential invalid (need to re-enroll)

Usage examples
--------------
    # First-time enrollment (from an elevated command prompt):
    python main.py enroll cgc_abc123def456...

    # Run the collector (foreground):
    python main.py run

    # Check status:
    python main.py status

    # Test connectivity without enrolling:
    python main.py test-connection

    # Force re-enroll (clears credential):
    python main.py clear-credential
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import signal
import socket
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Local imports — sys.path already has this file's directory
from config import (
    CollectorConfig,
    LOG_FILE,
    PROGRAM_DATA_DIR,
    configure_logging,
)
from credential_store import (
    clear_credential,
    load_credential,
    store_credential,
)
from api_client import ApiClient, HealthProbeResult
from event_queue import EventQueue
from event_log_reader import EventLogReader
from event_normalizer import normalize
from event_sender import EventSender
from heartbeat_worker import HeartbeatWorker


logger = logging.getLogger(__name__)


# ============================================================================
# EXIT CODES
# ============================================================================

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFIG_ERROR = 2
EXIT_NOT_ENROLLED = 3
EXIT_CREDENTIAL_INVALID = 4


# ============================================================================
# HARDWARE FINGERPRINT
# ============================================================================

def _compute_hardware_fingerprint() -> str | None:
    """
    Compute a stable device fingerprint in the format ``sha256:<hex>``.

    Inputs:
        - MAC address (from ``uuid.getnode()``)
        - Hostname

    The MAC is the primary signal. Hostname is included so that two
    devices sharing a MAC (rare — MAC cloning) still get distinct
    fingerprints.

    Returns None if neither input is available (very unusual).
    """
    parts: list[str] = []
    try:
        mac = uuid.getnode()
        if mac and not (mac >> 40) & 1:  # not a random MAC
            parts.append(f"mac:{mac:012x}")
    except Exception:
        pass

    try:
        host = socket.gethostname()
        if host:
            parts.append(f"host:{host.lower()}")
    except Exception:
        pass

    if not parts:
        return None

    payload = "|".join(sorted(parts))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


# ============================================================================
# READER LOOP
# ============================================================================

def _reader_loop(
    config: CollectorConfig,
    reader: EventLogReader,
    queue: EventQueue,
    stop_event: threading.Event,
    heartbeat: HeartbeatWorker,
) -> None:
    """
    Main reader loop. Runs in the main thread.

    Reads events from Windows Event Logs, normalizes, and enqueues.
    Exits when ``stop_event`` is set OR when the heartbeat thread
    dies (indicating a permanent credential failure).
    """
    logger.info(
        "Reader loop started",
        extra={
            "channels": list(config.event_channels),
            "poll_seconds": config.read_poll_seconds,
        },
    )

    poll_interval = float(config.read_poll_seconds)

    while not stop_event.is_set():
        # ── Check heartbeat health — if it stopped, the credential is dead
        if not heartbeat.is_running:
            logger.error(
                "Heartbeat worker has stopped — credential is likely "
                "revoked or expired. Stopping collector. Re-enroll "
                "with: python main.py enroll <new-token>"
            )
            stop_event.set()
            break

        try:
            events_read = 0
            for raw_event in reader.poll():
                if stop_event.is_set():
                    break

                payload = normalize(raw_event)
                if payload is None:
                    continue

                try:
                    queue.enqueue(payload)
                    events_read += 1
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Failed to enqueue event",
                        extra={"error": str(exc)[:200]},
                    )

            if events_read == 0:
                # Nothing new — sleep full interval
                stop_event.wait(timeout=poll_interval)
            else:
                # Events were read; more might be waiting. Yield briefly
                # so we check stop_event and heartbeat health.
                logger.debug(
                    "Reader poll complete",
                    extra={"events_read": events_read},
                )
                stop_event.wait(timeout=0.1)

        except KeyboardInterrupt:
            raise

        except Exception:  # noqa: BLE001
            # A reader poll failing (access denied, channel missing) is
            # not fatal — log and continue.
            logger.exception("Reader poll failed — continuing")
            stop_event.wait(timeout=poll_interval)

    logger.info("Reader loop stopped")


# ============================================================================
# COMMAND HANDLERS
# ============================================================================

def _cmd_run(args: argparse.Namespace) -> int:
    """Start the collector — the main operational command."""
    # ── Load config
    try:
        config = CollectorConfig.load()
    except RuntimeError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    configure_logging(config)

    logger.info(
        "CyberGuard AI Windows Collector starting",
        extra={
            **config.to_log_dict(),
            "log_file": str(LOG_FILE),
            "program_data_dir": str(PROGRAM_DATA_DIR),
        },
    )

    # ── Not enrolled?
    if not config.is_enrolled:
        print(
            "Collector is not enrolled.\n"
            "Run: python main.py enroll <enrollment-token>\n"
            "Get the token from the CyberGuard dashboard "
            "(Devices → Connect Device → Windows).",
            file=sys.stderr,
        )
        return EXIT_NOT_ENROLLED

    # ── Credential decryptable?
    credential = load_credential(config)
    if not credential:
        print(
            "Stored credential is not decryptable (wrong user, wrong "
            "machine, or corrupt file).\n"
            "Run: python main.py clear-credential\n"
            "Then: python main.py enroll <new-token>",
            file=sys.stderr,
        )
        return EXIT_CREDENTIAL_INVALID

    # ── Construct components
    try:
        client = ApiClient(config)
        queue = EventQueue(max_queue_size=config.max_queue_size)
        reader = EventLogReader(
            channels=list(config.event_channels),
            max_events_per_poll=500,
            event_ids_to_capture=list(config.event_ids_to_capture),
        )
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to initialize collector: {exc}", file=sys.stderr)
        return EXIT_ERROR

    sender = EventSender(config, queue, client)
    heartbeat = HeartbeatWorker(
        config=config,
        client=client,
        queue=queue,
        sender_stats_callback=sender.stats,
    )

    # ── Probe backend once at startup (informational, not blocking)
    probe = client.probe_health()
    if not probe.reachable:
        logger.warning(
            "Backend unreachable at startup — collector will buffer "
            "events until the connection is restored.",
            extra={"error": probe.error_message},
        )
    elif probe.db_ok is False:
        logger.warning(
            "Backend reachable but its database is down — sends will "
            "fail until resolved.",
        )
    else:
        logger.info("Backend reachable and healthy")

    # ── Set up stop signal (Ctrl+C and SIGTERM both trigger graceful stop)
    stop_event = threading.Event()

    def _signal_handler(signum: int, frame) -> None:  # noqa: ARG001
        logger.info("Received signal %d — initiating graceful shutdown", signum)
        stop_event.set()

    try:
        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)
    except (ValueError, OSError):
        # Signal handling may not be available in unusual environments
        # (e.g. running inside certain test harnesses). Ctrl+C still works.
        pass

    # ── Start background threads
    sender_thread = threading.Thread(
        target=sender.run_forever,
        args=(stop_event,),
        name="cyberguard-sender",
        daemon=True,
    )
    heartbeat_thread = threading.Thread(
        target=heartbeat.run_forever,
        args=(stop_event,),
        name="cyberguard-heartbeat",
        daemon=True,
    )
    sender_thread.start()
    heartbeat_thread.start()

    logger.info(
        "Collector running",
        extra={
            "sender_thread": sender_thread.name,
            "heartbeat_thread": heartbeat_thread.name,
        },
    )

    # ── Run reader loop in main thread (blocks until stop)
    exit_code = EXIT_OK
    try:
        _reader_loop(
            config=config,
            reader=reader,
            queue=queue,
            stop_event=stop_event,
            heartbeat=heartbeat,
        )
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received — stopping")
        stop_event.set()
    except Exception:
        logger.exception("Fatal error in reader loop")
        exit_code = EXIT_ERROR
        stop_event.set()

    # ── Graceful shutdown
    logger.info("Shutting down...")
    stop_event.set()

    # Sender needs time to finish any in-flight request
    sender_thread.join(timeout=15.0)
    if sender_thread.is_alive():
        logger.warning("Sender thread did not stop within 15s — leaving as daemon")

    heartbeat_thread.join(timeout=15.0)
    if heartbeat_thread.is_alive():
        logger.warning("Heartbeat thread did not stop within 15s — leaving as daemon")

    # Final queue state
    try:
        queue_stats = queue.stats()
        logger.info(
            "Final queue state",
            extra=queue_stats,
        )
    except Exception:  # noqa: BLE001
        pass

    # Close the DB cleanly
    queue.close()

    logger.info(
        "Collector stopped",
        extra={
            "exit_code": exit_code,
            "sender_stats": sender.stats(),
            "heartbeat_stats": heartbeat.stats(),
        },
    )

    return exit_code


def _cmd_enroll(args: argparse.Namespace) -> int:
    """Redeem an enrollment token and store the resulting credential."""
    try:
        config = CollectorConfig.load()
    except RuntimeError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    configure_logging(config)

    token = args.token.strip()
    if not token:
        print("Enrollment token is empty.", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    if config.is_enrolled:
        existing = load_credential(config)
        if existing:
            print(
                "Collector is already enrolled.\n"
                "If you want to re-enroll (e.g. after revoking the "
                "old credential), run:\n"
                "  python main.py clear-credential\n"
                "  python main.py enroll <new-token>",
                file=sys.stderr,
            )
            return EXIT_CREDENTIAL_INVALID

    print(f"Enrolling collector {config.collector_id} ...")
    print(f"Backend: {config.backend_url}")

    client = ApiClient(config)
    fingerprint = _compute_hardware_fingerprint()

    result = client.enroll(
        plaintext_token=token,
        agent_version=config.agent_version,
        hardware_fingerprint=fingerprint,
    )

    if not result.success:
        print(
            f"Enrollment failed: {result.error_code}\n"
            f"  {result.error_message}",
            file=sys.stderr,
        )
        return EXIT_ERROR

    if not result.plaintext_credential:
        print(
            "Backend returned success but no credential. This is a bug "
            "in the backend — contact support.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    # Persist the credential (encrypted) and any updated settings
    store_credential(config, result.plaintext_credential)
    if result.heartbeat_interval_seconds:
        config.heartbeat_interval_seconds = int(
            result.heartbeat_interval_seconds
        )
    config.save()

    print()
    print("Enrollment successful.")
    print(f"  Collector ID:       {config.collector_id}")
    print(f"  Credential prefix:  {result.credential_prefix}")
    print(f"  Config saved to:    {PROGRAM_DATA_DIR / 'config.json'}")
    print()
    print("Start the collector with:  python main.py run")
    return EXIT_OK


def _cmd_status(args: argparse.Namespace) -> int:  # noqa: ARG001
    """Print the collector's current status."""
    try:
        config = CollectorConfig.load()
    except RuntimeError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    print("CyberGuard AI Windows Collector — Status")
    print("=" * 55)
    print(f"  Collector ID:       {config.collector_id}")
    print(f"  Backend URL:        {config.backend_url}")
    print(f"  Enrolled:           {config.is_enrolled}")
    print(f"  Config directory:   {PROGRAM_DATA_DIR}")
    print(f"  Log file:           {LOG_FILE}")
    print(f"  Agent version:      {config.agent_version}")
    print()
    print(f"  Event channels:     {', '.join(config.event_channels)}")
    print(f"  Event ID filter:    "
          f"{'all' if not config.event_ids_to_capture else config.event_ids_to_capture}")
    print(f"  Batch size:         {config.batch_size}")
    print(f"  Batch interval:     {config.batch_interval_seconds}s")
    print(f"  Heartbeat interval: {config.heartbeat_interval_seconds}s")
    print()

    # Credential availability
    credential = load_credential(config)
    if credential:
        print("  Credential:         Available (decryptable)")
        try:
            prefix = credential[:12]
            print(f"  Credential prefix:  {prefix}")
        except Exception:
            pass
    elif config.is_enrolled:
        print("  Credential:         STORED BUT UNDECRYPTABLE "
              "(wrong machine/user? Run: clear-credential)")
    else:
        print("  Credential:         Not enrolled")

    # Queue size
    try:
        queue = EventQueue(max_queue_size=config.max_queue_size)
        qstats = queue.stats()
        print()
        print(f"  Queue:              {qstats['count']} events pending")
        if qstats.get("oldest_age_seconds") is not None:
            age = qstats["oldest_age_seconds"]
            print(f"  Oldest event:       {age}s ago ({age // 60}m)")
        queue.close()
    except Exception as exc:  # noqa: BLE001
        print(f"  Queue:              Unable to read ({exc})")

    return EXIT_OK


def _cmd_test_connection(args: argparse.Namespace) -> int:  # noqa: ARG001
    """Probe the backend's /health endpoint."""
    try:
        config = CollectorConfig.load()
    except RuntimeError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    print(f"Testing connection to {config.backend_url} ...")
    client = ApiClient(config)
    result: HealthProbeResult = client.probe_health()

    if not result.reachable:
        print(f"  REACHABLE:  NO")
        print(f"  Error:      {result.error_message}")
        print()
        print("Check:")
        print("  - Is the backend running?")
        print("  - Is the URL correct in config.json?")
        print("  - Any firewall blocking the connection?")
        return EXIT_ERROR

    print(f"  REACHABLE:  YES")
    if result.status_code is not None:
        print(f"  Status:     {result.status_code}")
    if result.db_ok is not None:
        print(f"  DB health:  {'OK' if result.db_ok else 'DOWN'}")
        if not result.db_ok:
            print()
            print("Backend is up but its database is down. Event sends")
            print("will fail until resolved. Contact the backend operator.")
            return EXIT_ERROR

    print()
    print("Backend is healthy and ready to receive events.")
    return EXIT_OK


def _cmd_clear_credential(args: argparse.Namespace) -> int:  # noqa: ARG001
    """Remove the stored credential from config.json (forces re-enroll)."""
    try:
        config = CollectorConfig.load()
    except RuntimeError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    if not config.credential:
        print("No credential to clear — collector is already unenrolled.")
        return EXIT_OK

    answer = input(
        "This will remove the current credential and require re-enrollment. "
        "Continue? [y/N] "
    ).strip().lower()
    if answer not in ("y", "yes"):
        print("Cancelled.")
        return EXIT_OK

    clear_credential(config)
    config.save()

    print()
    print("Credential cleared. The collector is now unenrolled.")
    print("To re-enroll: python main.py enroll <new-token>")
    return EXIT_OK


def _cmd_version(args: argparse.Namespace) -> int:  # noqa: ARG001
    """Print collector version and environment info."""
    print("CyberGuard AI — Windows Collector")
    try:
        config = CollectorConfig.load()
        print(f"  Agent version:    {config.agent_version}")
        print(f"  Python:           {sys.version.split()[0]}")
        print(f"  Platform:         {sys.platform}")
        print(f"  Program data dir: {PROGRAM_DATA_DIR}")
    except Exception:  # noqa: BLE001
        print(f"  Python:           {sys.version.split()[0]}")
        print(f"  Platform:         {sys.platform}")
    return EXIT_OK


# ============================================================================
# ARGUMENT PARSER
# ============================================================================

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberguard-collector",
        description=(
            "CyberGuard AI Windows Collector — monitors local Windows "
            "event logs and streams security events to the CyberGuard "
            "backend."
        ),
    )
    subparsers = parser.add_subparsers(
        dest="command", required=True, metavar="<command>",
    )

    # run
    run_parser = subparsers.add_parser(
        "run",
        help="Start the collector (the normal operational command).",
    )
    run_parser.set_defaults(func=_cmd_run)

    # enroll
    enroll_parser = subparsers.add_parser(
        "enroll",
        help="Redeem an enrollment token and store the resulting credential.",
    )
    enroll_parser.add_argument(
        "token",
        help=(
            "The plaintext enrollment token from the CyberGuard dashboard "
            "(looks like cgc_XXXXXXXX...)."
        ),
    )
    enroll_parser.set_defaults(func=_cmd_enroll)

    # status
    status_parser = subparsers.add_parser(
        "status",
        help="Show current collector status (enrollment, queue, config).",
    )
    status_parser.set_defaults(func=_cmd_status)

    # test-connection
    test_parser = subparsers.add_parser(
        "test-connection",
        help="Probe the backend's /health endpoint to verify connectivity.",
    )
    test_parser.set_defaults(func=_cmd_test_connection)

    # clear-credential
    clear_parser = subparsers.add_parser(
        "clear-credential",
        help="Remove the stored credential (forces re-enrollment).",
    )
    clear_parser.set_defaults(func=_cmd_clear_credential)

    # version
    version_parser = subparsers.add_parser(
        "version",
        help="Show collector version and environment info.",
    )
    version_parser.set_defaults(func=_cmd_version)

    return parser


# ============================================================================
# MAIN
# ============================================================================

def main(argv: list[str] | None = None) -> int:
    """Parse arguments, dispatch to the appropriate command."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        return EXIT_ERROR
    except Exception:
        logger.exception("Unhandled error in command %s", args.command)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())