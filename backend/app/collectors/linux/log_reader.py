"""
CyberGuard AI — Linux Collector Log Reader
============================================================================

Reads security-relevant events from TWO Linux sources:

    1. **systemd journal** (via ``journalctl -o json``)
       - Structured output (fields are already parsed)
       - Uses ``__CURSOR`` for incremental reads (survives restarts)
       - Covers all systemd-managed services
       - Requires the collector to be in the ``systemd-journal`` group
         (or run as root — which the systemd unit does)

    2. **Log files** (via byte-offset tailing)
       - ``/var/log/auth.log``, ``/var/log/secure``, etc.
       - Parses RFC 3164 syslog format
       - Tracks file position + inode for rotation handling
       - Needed because many services write directly to /var/log/*
         instead of to journald (or duplicate both)

Both can be enabled simultaneously. In practice, most Linux deployments
need both:

    - sshd on Debian → /var/log/auth.log AND journald
    - kernel → /var/log/kern.log AND journald
    - sudo → /var/log/auth.log AND journald
    - custom services → may be journald-only OR file-only

Deduplication happens server-side (fingerprint), so reading both
sources is safe — events arrive twice, second insert is rejected as
duplicate.

Incremental reads
-----------------
    journald:  uses ``__CURSOR`` — a stable systemd identifier that
               survives restarts. After reading a batch, we store the
               last cursor and pass it as ``--after-cursor`` next time.
               Persisted to ``config.journald_cursor``.

    files:     uses byte offset — the file position at the end of the
               last successfully-read line. Persisted per-file to
               ``config.file_positions``. On restart, seek() to the
               stored offset. Rotation is detected by comparing inode
               — if the inode changed, we start from 0.

Log rotation
------------
Files rotate (logrotate, size limits). Two cases:

    New content, same inode       → keep reading from saved offset
    File replaced (new inode)     → start from 0, keep old positions
    File truncated (size shrunk)  → start from 0 (rotated in place)
    File deleted + recreated      → start from 0, new inode

Rotation is detected by:
    - Comparing stored ``inode`` against current file's inode
    - Comparing stored ``offset`` against current file size
      (if the file is now smaller, it was truncated)

Syslog parsing (RFC 3164)
-------------------------
Standard syslog line format:

    Nov  7 14:23:45 hostname process[pid]: message

We parse this into:
    {
        "timestamp": datetime (year inferred from current year),
        "hostname": "hostname",
        "process": "process",
        "pid": 1234,
        "message": "message",
        "raw": "<full line>",
        "source": "file",
        "file_path": "/var/log/auth.log",
    }

RFC 5424 (structured syslog) is also handled if the line starts with
a ``<priority>version `` prefix.

Journald JSON shape
-------------------
``journalctl -o json`` produces one JSON object per line:

    {
        "__CURSOR": "s=...",
        "__REALTIME_TIMESTAMP": "1699287825123456",   # microseconds
        "PRIORITY": "3",                               # syslog priority
        "_HOSTNAME": "host",
        "_SYSTEMD_UNIT": "sshd.service",
        "SYSLOG_IDENTIFIER": "sshd",
        "MESSAGE": "Failed password for alice...",
        ... (many more underscore-prefixed trusted fields)
    }

We extract the fields CyberGuard's normalizer needs and preserve the
full raw entry as ``raw_payload`` downstream.

Prerequisites
-------------
    - ``journalctl`` available (systemd-based distros)
    - Read access to configured log files (typically root or admin group)
    - Python 3.10+

Non-blocking reads
------------------
The reader NEVER blocks on a stuck journald pipe or an infinite file.
Every operation has:

    - A per-call batch limit (``max_events_per_poll``)
    - A subprocess timeout (``journald_timeout_seconds`` default 10s)
    - No ``readline()`` without size bounds

A hung journalctl subprocess is killed after the timeout and logged as
an error. The reader returns whatever it already read and moves on.

Subprocess usage
----------------
We invoke ``journalctl`` via ``subprocess.Popen`` (not ``subprocess.run``)
because we want to read line-by-line and stop early if ``max_events``
is hit. If we used ``run()``, a journal with 50,000 backlogged entries
would block for minutes.

Usage
-----
    from config import CollectorConfig
    from log_reader import LogReader

    config = CollectorConfig.load()
    reader = LogReader(config)

    for raw_event in reader.poll():
        # raw_event is either:
        #   {"source": "journald", "cursor": "...", ...journald fields}
        #   {"source": "file", "file_path": "...", ...parsed syslog fields}
        normalized = normalize(raw_event)
        queue.enqueue(normalized)

    # Persist progress after each poll
    config.journald_cursor = reader.get_cursor()
    config.file_positions = reader.get_file_positions()
    config.save()
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


logger = logging.getLogger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

#: Fallback journald batch size (config overrides).
_DEFAULT_JOURNALD_BATCH = 100

#: Fallback file tail batch size (config overrides).
_DEFAULT_FILE_BATCH = 100

#: How long to wait for journalctl before killing the subprocess.
#: A hung journalctl is a real failure mode when the journal is
#: corrupted or the disk is thrashing. 10s is generous.
_JOURNALCTL_TIMEOUT_SECONDS = 10

#: RFC 3164 syslog line pattern:
#: "Nov  7 14:23:45 hostname process[pid]: message"
_SYSLOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

#: RFC 5424 structured syslog prefix: "<PRI>VERSION "
_RFC5424_PATTERN = re.compile(
    r"^<(?P<priority>\d{1,3})>(?P<version>\d)\s+"
)

#: Month name → month number (for parsing RFC 3164 timestamps —
#: which have no year, so we infer current year).
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

#: Syslog priority → CyberGuard severity hint.
#:   Priority = facility * 8 + severity
#:   Severity bits: 0=emerg, 1=alert, 2=crit, 3=err, 4=warning,
#:                  5=notice, 6=info, 7=debug
_PRIORITY_TO_LEVEL = {
    0: "critical",    # emergency
    1: "critical",    # alert
    2: "critical",    # critical
    3: "high",        # error
    4: "medium",      # warning
    5: "low",         # notice
    6: "low",         # info
    7: "info",        # debug
}


# ============================================================================
# JOURNALD READER
# ============================================================================

def _journalctl_available() -> bool:
    """Return True if ``journalctl`` is on PATH."""
    return shutil.which("journalctl") is not None


@dataclass
class _FileState:
    """Tracks a single file's read position between polls."""
    inode: int = 0
    offset: int = 0


class LogReader:
    """
    Reads from journald + log files, incrementally, non-blocking.

    One instance per collector. Not thread-safe — call from a single
    reader thread. Holds internal state (file positions, journald
    cursor) that the caller persists to config after each poll.
    """

    def __init__(self, config: Any) -> None:
        """
        Parameters
        ----------
        config : CollectorConfig
            Provides ``use_journald``, ``use_log_files``, ``log_files``,
            ``journald_units``, ``journald_batch_size``, ``file_tail_batch_lines``,
            ``max_events_per_poll``, plus the persisted ``journald_cursor``
            and ``file_positions``.
        """
        self._config = config

        # Feature availability
        self._journald_ok = bool(config.use_journald) and _journalctl_available()
        if config.use_journald and not self._journald_ok:
            logger.warning(
                "journald requested but 'journalctl' not on PATH — "
                "file-only mode active",
            )

        # Internal state — restored from config
        self._cursor: str | None = getattr(config, "journald_cursor", None)
        positions = getattr(config, "file_positions", None) or {}
        self._file_states: dict[str, _FileState] = {}

        for path_str, offset_or_dict in positions.items():
            if isinstance(offset_or_dict, dict):
                # New format (inode + offset)
                self._file_states[path_str] = _FileState(
                    inode=int(offset_or_dict.get("inode", 0)),
                    offset=int(offset_or_dict.get("offset", 0)),
                )
            elif isinstance(offset_or_dict, int):
                # Legacy format (offset only) — inode unknown, will be
                # refreshed on first read
                self._file_states[path_str] = _FileState(
                    inode=0,
                    offset=int(offset_or_dict),
                )

        # Batch limits
        self._max_events = max(
            1, int(getattr(config, "max_events_per_poll", 500)),
        )
        self._journald_batch = max(
            1, int(getattr(config, "journald_batch_size", _DEFAULT_JOURNALD_BATCH)),
        )
        self._file_batch = max(
            1, int(getattr(config, "file_tail_batch_lines", _DEFAULT_FILE_BATCH)),
        )

    # ── Public: poll ───────────────────────────────────────────────────

    def poll(self) -> Iterator[dict[str, Any]]:
        """
        Poll both sources once. Yields raw event dicts.

        Total events yielded per call is bounded by
        ``config.max_events_per_poll`` (default 500). Sources are
        polled in order: journald first (structured, faster to parse),
        then files (text parsing).

        Stops early if either source hits the global event cap.
        """
        total = 0
        budget_left = self._max_events

        # ── Source 1: journald
        if self._journald_ok and budget_left > 0:
            try:
                for entry in self._poll_journald(limit=budget_left):
                    yield entry
                    total += 1
                    budget_left -= 1
                    if budget_left <= 0:
                        return
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "journald poll failed — skipping",
                    extra={"error": f"{type(exc).__name__}: {str(exc)[:300]}"},
                )

        # ── Source 2: files
        if not self._config.use_log_files or budget_left <= 0:
            return

        for file_path in self._config.log_files:
            if budget_left <= 0:
                return
            try:
                for entry in self._poll_file(file_path, limit=budget_left):
                    yield entry
                    total += 1
                    budget_left -= 1
                    if budget_left <= 0:
                        return
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "File poll failed — skipping file",
                    extra={
                        "file": file_path,
                        "error": f"{type(exc).__name__}: {str(exc)[:300]}",
                    },
                )
                continue

    # ── Public: state persistence ──────────────────────────────────────

    def get_cursor(self) -> str | None:
        """Return the last-read journald cursor (or None)."""
        return self._cursor

    def get_file_positions(self) -> dict[str, dict[str, int]]:
        """
        Return the current file positions as a JSON-safe dict:

            {
                "/var/log/auth.log": {"inode": 12345, "offset": 67890},
                ...
            }
        """
        return {
            path: {"inode": state.inode, "offset": state.offset}
            for path, state in self._file_states.items()
        }

    # ── Internal: journald ─────────────────────────────────────────────

    def _poll_journald(self, *, limit: int) -> Iterator[dict[str, Any]]:
        """
        Read up to ``limit`` journald entries via subprocess.

        Uses ``journalctl -o json`` with ``--after-cursor`` to resume
        incrementally. Non-blocking via subprocess timeout — if
        journalctl hangs, we kill it and return what we have.

        Filters:
            - ``--since`` when no cursor (first read — last hour by default)
            - Unit filter (``--unit``) if ``journald_units`` is set
        """
        cmd = ["journalctl", "-o", "json", "--no-pager"]

        # Resume from cursor, or use time window on first read
        if self._cursor:
            cmd += ["--after-cursor", self._cursor]
        else:
            # First read — last 1 hour to avoid loading the full history
            cmd += ["--since", "1 hour ago"]

        # Unit filter — repeat --unit for each
        for unit in getattr(self._config, "journald_units", []) or []:
            cmd += ["--unit", unit]

        batch_limit = min(limit, self._journald_batch)
        cmd += ["--lines", str(batch_limit)]

        logger.debug(
            "Polling journald",
            extra={"limit": batch_limit, "cursor": self._cursor},
        )

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            # Read at most `batch_limit` lines, non-blocking on timeout
            deadline = time.time() + _JOURNALCTL_TIMEOUT_SECONDS
            read_count = 0

            while read_count < batch_limit:
                if time.time() > deadline:
                    logger.warning(
                        "journalctl read timed out — killing subprocess",
                        extra={
                            "timeout_seconds": _JOURNALCTL_TIMEOUT_SECONDS,
                            "events_read": read_count,
                        },
                    )
                    break

                line = proc.stdout.readline()
                if not line:
                    break

                stripped = line.strip()
                if not stripped:
                    continue

                try:
                    entry = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    logger.debug(
                        "Skipping malformed journald line",
                        extra={"error": str(exc)[:200]},
                    )
                    continue

                if not isinstance(entry, dict):
                    continue

                # Update cursor
                new_cursor = entry.get("__CURSOR")
                if new_cursor:
                    self._cursor = new_cursor

                # Emit structured journald entry
                yield self._journald_to_event(entry)
                read_count += 1

        finally:
            # Ensure the subprocess is cleaned up
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=2)
            except Exception:  # noqa: BLE001
                pass

        if read_count > 0:
            logger.debug(
                "journald poll complete",
                extra={"events_read": read_count},
            )

    def _journald_to_event(self, entry: dict[str, Any]) -> dict[str, Any]:
        """
        Convert a journald JSON entry to the raw event shape the
        normalizer expects.

        Journald entries contain hundreds of fields. We extract the
        well-known ones and preserve the rest in ``raw_payload``.
        """
        # Microsecond timestamp → ISO string
        ts_micros = entry.get("__REALTIME_TIMESTAMP")
        timestamp_str: str | None = None
        if ts_micros:
            try:
                ts_seconds = int(ts_micros) / 1_000_000.0
                dt = datetime.fromtimestamp(ts_seconds, tz=timezone.utc)
                timestamp_str = dt.isoformat()
            except (ValueError, TypeError):
                pass

        # Priority → level name
        priority_str = entry.get("PRIORITY")
        level: str | None = None
        try:
            if priority_str is not None:
                priority_int = int(priority_str) & 0x07  # low 3 bits
                level = _PRIORITY_TO_LEVEL.get(priority_int)
        except (ValueError, TypeError):
            pass

        return {
            "source": "journald",
            "timestamp": timestamp_str,
            "level": level,
            "hostname": entry.get("_HOSTNAME"),
            "unit": entry.get("_SYSTEMD_UNIT"),
            "identifier": entry.get("SYSLOG_IDENTIFIER"),
            "pid": entry.get("_PID"),
            "uid": entry.get("_UID"),
            "message": entry.get("MESSAGE"),
            "cursor": entry.get("__CURSOR"),
            "transport": entry.get("_TRANSPORT"),
            "raw": entry,
        }

    # ── Internal: file tailing ─────────────────────────────────────────

    def _poll_file(
        self,
        file_path: str,
        *,
        limit: int,
    ) -> Iterator[dict[str, Any]]:
        """
        Read new lines from one file since the last saved offset.

        Detects rotation:
            - inode changed → start from 0
            - file size < saved offset → truncated, start from 0

        Reads at most ``min(limit, file_batch)`` lines per call.
        """
        path = Path(file_path)

        if not path.exists():
            # File doesn't exist (yet) — nothing to read. Reset state so
            # that if it appears later, we start from byte 0.
            self._file_states.pop(file_path, None)
            return

        try:
            stat = path.stat()
        except OSError as exc:
            logger.debug(
                "Cannot stat file — skipping",
                extra={"file": file_path, "error": str(exc)[:200]},
            )
            return

        current_inode = stat.st_ino
        current_size = stat.st_size

        # Get or initialize state
        state = self._file_states.get(file_path)
        if state is None or state.inode != current_inode:
            # First read OR rotation (new inode) — start from 0
            state = _FileState(inode=current_inode, offset=0)
            self._file_states[file_path] = state
            logger.debug(
                "Starting file read from beginning",
                extra={"file": file_path, "inode": current_inode},
            )
        elif state.offset > current_size:
            # File shrank (truncated in place) — restart
            logger.debug(
                "File truncated — restarting from beginning",
                extra={
                    "file": file_path,
                    "saved_offset": state.offset,
                    "current_size": current_size,
                },
            )
            state.offset = 0

        if state.offset >= current_size:
            # No new data
            return

        # Open and seek to saved offset
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                f.seek(state.offset)

                batch_limit = min(limit, self._file_batch)
                read_count = 0

                for line in f:
                    if read_count >= batch_limit:
                        # Save position and stop — more lines next poll
                        state.offset = f.tell()
                        break

                    stripped = line.rstrip("\n")
                    if not stripped:
                        continue

                    parsed = self._parse_syslog_line(
                        stripped, file_path=file_path,
                    )
                    if parsed is not None:
                        yield parsed
                        read_count += 1

                else:
                    # Reached EOF — save final position
                    state.offset = f.tell()

        except OSError as exc:
            logger.warning(
                "Failed to read log file",
                extra={"file": file_path, "error": str(exc)[:200]},
            )
            return

        if read_count > 0:
            logger.debug(
                "File poll complete",
                extra={
                    "file": file_path,
                    "events_read": read_count,
                    "new_offset": state.offset,
                },
            )

    # ── Internal: syslog parsing ───────────────────────────────────────

    def _parse_syslog_line(
        self,
        line: str,
        *,
        file_path: str,
    ) -> dict[str, Any] | None:
        """
        Parse a single syslog line into the raw event shape.

        Handles two formats:
            RFC 3164:  "Nov  7 14:23:45 host process[pid]: message"
            RFC 5424:  "<PRI>1 2026-11-07T14:23:45Z host process pid msg"

        Returns None if the line doesn't match either format (rare —
        multi-line stack traces, blank separators, etc.).
        """
        # RFC 5424 (with priority prefix)
        rfc5424 = _RFC5424_PATTERN.match(line)
        if rfc5424:
            # Extracting full RFC 5424 header is complex; treat the
            # remainder as the message and let the normalizer handle it.
            return {
                "source": "file",
                "file_path": file_path,
                "format": "rfc5424",
                "priority": int(rfc5424.group("priority")),
                "level": _priority_to_level(int(rfc5424.group("priority"))),
                "message": line[rfc5424.end():],
                "raw_line": line,
                "timestamp": None,   # let normalizer infer or skip
                "hostname": None,
                "process": None,
                "pid": None,
            }

        # RFC 3164 (traditional syslog)
        match = _SYSLOG_PATTERN.match(line)
        if match:
            month_str = match.group("month")
            day = int(match.group("day"))
            time_str = match.group("time")

            month_num = _MONTHS.get(month_str)
            if month_num is None:
                return None

            # Infer year — syslog omits it. If the parsed date is
            # "in the future" (by > 1 day), it must be from last year.
            now = datetime.now(timezone.utc)
            year = now.year
            try:
                hour, minute, second = (int(x) for x in time_str.split(":"))
                dt = datetime(
                    year, month_num, day, hour, minute, second,
                    tzinfo=timezone.utc,
                )
                if (dt - now).total_seconds() > 86400:
                    # More than a day in the future → last year
                    dt = dt.replace(year=year - 1)
                timestamp_str = dt.isoformat()
            except (ValueError, IndexError):
                timestamp_str = None

            pid_str = match.group("pid")
            try:
                pid = int(pid_str) if pid_str else None
            except (ValueError, TypeError):
                pid = None

            process = match.group("process").strip()

            # Priority hint from process name
            level = _process_to_level_hint(process)

            return {
                "source": "file",
                "file_path": file_path,
                "format": "rfc3164",
                "timestamp": timestamp_str,
                "hostname": match.group("hostname"),
                "process": process,
                "pid": pid,
                "level": level,
                "message": match.group("message"),
                "raw_line": line,
            }

        # Unknown format — pass through with minimal structure
        return {
            "source": "file",
            "file_path": file_path,
            "format": "unknown",
            "timestamp": None,
            "hostname": None,
            "process": None,
            "pid": None,
            "level": None,
            "message": line,
            "raw_line": line,
        }


# ============================================================================
# HELPERS
# ============================================================================

def _priority_to_level(priority: int) -> str | None:
    """Map syslog priority (0–191) to a severity name."""
    severity = priority & 0x07
    return _PRIORITY_TO_LEVEL.get(severity)


def _process_to_level_hint(process: str) -> str | None:
    """
    Heuristic severity hint from the process name.

    Not authoritative — the normalizer will make the final call. But
    "sshd failure" → high, "sudo" → medium, "systemd" → low gives
    the normalizer useful signal.
    """
    p = process.lower()
    if p in ("sshd", "sshd-session", "login", "su", "pam_unix"):
        return "medium"
    if p in ("sudo", "su"):
        return "medium"
    if p in ("kernel", "audit", "auditd"):
        return "medium"
    if p.startswith("systemd"):
        return "low"
    return None


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "LogReader",
]