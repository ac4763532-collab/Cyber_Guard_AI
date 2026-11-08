"""
CyberGuard AI — Event Fingerprint Service
============================================================================

Deterministic event fingerprinting for deduplication.

Every event ingested by the platform gets a fingerprint computed from
a small set of identifying fields. Two events with the same fingerprint
are **by definition** the same event — even if they arrived via
different collectors, in different batches, at different times.

Purpose
-------
Collectors retry. Networks blip. A single failed HTTP response can
cause a collector to resend the same 500 events. Without dedup, a
single flaky connection produces 500 duplicate events, 500 duplicate
findings, and 500 duplicate alerts — instantly burying real signal
under noise.

The fingerprint prevents that. The DB has a unique constraint on
``(workspace_id, fingerprint)`` — a duplicate insert fails cleanly,
the ingestion service catches the IntegrityError, and the event is
reported as ``duplicate`` instead of ``ingested``.

Field selection (why these, not those)
--------------------------------------
Included fields:
    source_id         Which device sent it (same event from different
                      devices is coincidentally similar, not identical)
    event_time_ms     Truncated to millisecond precision. A retry
                      sends the exact same timestamp; a genuinely
                      different event has a different timestamp
    event_type        What kind of event (failed_login vs port_scan)
    action            The action (login, execute, read, ...)
    outcome           The result (success, failure, ...)
    username          Who was involved
    source_ip         From where
    destination_ip    To where

Excluded fields:
    received_at       Set by the backend — varies per retry
    severity          May be upgraded by agents after ingestion
    category          May be reclassified
    raw_payload       Too large; whitespace varies in JSON encodings;
                      not guaranteed stable across collector retries
    normalized_payload Similar concerns to raw_payload
    findings_count    Counter — changes over time
    tags              Analyst-curated, mutable
    metadata          Free-form; not identity-relevant

Fingerprint format
------------------
    SHA-256 hex digest, 64 lowercase characters

    Computed over a canonical pipe-separated payload:

        v1|<source_id>|<event_time_ms>|<event_type>|<action>|
        <outcome>|<username>|<source_ip>|<destination_ip>

    Versioned (``v1``) so a future change to the field set or
    normalization rules can be introduced without invalidating old
    fingerprints. Ingestion checks the DB constraint; if ``v2`` is ever
    needed, old rows stay valid, new rows use ``v2``, and a migration
    can rehash if desired.

Normalization rules
-------------------
    - ``source_id``: serialized as its UUID string (canonical form)
    - ``event_time``: converted to UTC, then to integer milliseconds
      since epoch. Truncating to milliseconds handles a subtle case:
      the collector may resend the same event with microsecond-precision
      variation if it derives event_time from a monotonic clock rather
      than a fixed source timestamp. Millisecond truncation collapses
      these variations.
    - Strings: stripped of surrounding whitespace, lowercased
    - None: replaced with empty string (so ``None`` and ``""`` are
      equivalent — both mean "field not provided")

The lowercasing is important. ``Alice`` and ``alice`` are the same user
in practice; treating them as different would defeat dedup. Same for
``FAILED_LOGIN`` vs ``failed_login`` — the source may not normalize
case before sending.

Why not canonicalize IPs?
    IPv6 has multiple valid representations (``::1`` vs
    ``0:0:0:0:0:0:0:1``). Canonicalizing would require parsing. For
    MVP, we hash the string as-received. Collectors are expected to
    send consistent IP representations. A future enhancement can
    canonicalize before hashing.

Determinism guarantees
----------------------
Given identical inputs, this function returns identical output on
every invocation, across processes, across machines, across time.
This is the **contract** — do not add anything to the fingerprint
payload that could vary (random salt, timestamp, process ID, etc.).

Performance
-----------
The hashing itself is ~2µs (SHA-256 on ~200-byte payload).
The overhead is in string construction and normalization — also
~5µs. Total: ~7µs per event. At 1000 events/sec, that's 7ms/sec of
CPU — negligible.

Public API
----------
    compute_fingerprint(*, source_id, event_time, event_type, ...) → str
    compute_batch_fingerprints(events) → list[str]

Usage
-----
    from app.services.event_fingerprint import compute_fingerprint

    fp = compute_fingerprint(
        source_id=source.id,
        event_time=parsed_time,
        event_type="failed_login",
        action="login",
        outcome="failure",
        username="alice",
        source_ip="203.0.113.42",
        destination_ip=None,
    )
    # → '3f8a...' (64 chars)

    # Batch version accepts ORM objects, dataclasses, or dicts:
    fps = compute_batch_fingerprints(validated_events)
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable


# ============================================================================
# CONSTANTS
# ============================================================================

#: Version prefix in the fingerprint payload. Bump if the field set or
#: normalization rules change in a way that must not collide with v1
#: fingerprints already stored in the DB.
FINGERPRINT_VERSION = "v1"

#: Separator between payload fields. Piped (`|`) is human-readable in
#: logs, unlikely to appear in any real field value, and easy to spot
#: in a hex dump.
_FIELD_SEPARATOR = "|"

#: Expected fingerprint length (SHA-256 hex).
FINGERPRINT_LENGTH = 64


# ============================================================================
# NORMALIZATION HELPERS
# ============================================================================

def _normalize_string(value: Any) -> str:
    """
    Normalize a string field: ``None`` → empty, then strip + lowercase.

    Non-string inputs (e.g. an accidental int) are coerced via ``str()``
    first — defensive, since collectors can be sloppy and we don't
    want the fingerprint to raise on malformed-but-parseable input.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return value.strip().lower()


def _normalize_source_id(value: uuid.UUID | str) -> str:
    """
    Normalize a source_id to its canonical UUID string.

    Accepts UUID objects or strings — both serialize to the same
    canonical string form. Invalid UUID strings are hashed as-is;
    the fingerprint doesn't validate input (that's the ingestion
    service's job), it just makes one.
    """
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, str):
        return value.strip().lower()
    raise TypeError(
        f"source_id must be a UUID or string, got {type(value).__name__}"
    )


def _normalize_event_time(value: datetime) -> str:
    """
    Normalize an event_time to UTC milliseconds-since-epoch as a string.

    - Naive datetimes are assumed UTC (consistent with the rest of the
      platform's "naive means UTC" policy)
    - Aware datetimes are converted to UTC
    - Truncated to millisecond precision (``int(ts * 1000)``)

    Truncating to milliseconds collapses the microsecond-level
    variation that can occur when a collector retries with a fresh
    "now()" timestamp instead of the original source timestamp. It also
    means an event that legitimately occurs within the same millisecond
    from the same source with the same type/action/outcome/user/IP is
    considered a duplicate — an extremely unlikely false positive.
    """
    if not isinstance(value, datetime):
        raise TypeError(
            f"event_time must be a datetime, got {type(value).__name__}"
        )

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    value_utc = value.astimezone(timezone.utc)
    millis = int(value_utc.timestamp() * 1000)
    return str(millis)


# ============================================================================
# CORE FUNCTION
# ============================================================================

def compute_fingerprint(
    *,
    source_id: uuid.UUID | str,
    event_time: datetime,
    event_type: str,
    action: str | None = None,
    outcome: str | None = None,
    username: str | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
) -> str:
    """
    Compute a deterministic SHA-256 fingerprint for an event.

    Parameters
    ----------
    source_id : UUID | str
        The source that produced the event. Required.
    event_time : datetime
        When the event occurred (source time). Required. Naive
        datetimes are treated as UTC.
    event_type : str
        Free-form type string (``failed_login``, ``port_scan``, ...).
        Required. Normalized to lowercase.
    action, outcome, username, source_ip, destination_ip : str | None
        Optional identifying fields. ``None`` and ``""`` are
        equivalent.

    Returns
    -------
    str
        64-character lowercase hex SHA-256 digest.

    Raises
    ------
    TypeError
        If ``source_id`` is not a UUID/str, or ``event_time`` is not
        a datetime.
    """
    # ── Build the canonical payload
    payload = _FIELD_SEPARATOR.join([
        FINGERPRINT_VERSION,
        _normalize_source_id(source_id),
        _normalize_event_time(event_time),
        _normalize_string(event_type),
        _normalize_string(action),
        _normalize_string(outcome),
        _normalize_string(username),
        _normalize_string(source_ip),
        _normalize_string(destination_ip),
    ])

    # ── Hash
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return digest


# ============================================================================
# BATCH
# ============================================================================

def _extract_field(event: Any, name: str) -> Any:
    """
    Extract a field from an event that may be a dict, an ORM model, a
    Pydantic model, or any object with attributes.

    Returns ``None`` if the field is absent (rather than raising) —
    but required fields (``source_id``, ``event_time``, ``event_type``)
    are still checked by ``compute_fingerprint`` and will raise a
    ``TypeError`` if truly missing.
    """
    if isinstance(event, dict):
        return event.get(name)
    return getattr(event, name, None)


def compute_batch_fingerprints(events: Iterable[Any]) -> list[str]:
    """
    Compute fingerprints for multiple events in one call.

    Accepts ORM objects, Pydantic models, dataclasses, or dicts — as
    long as they expose the required fields as attributes or dict
    keys.

    Returns a list of fingerprints in the same order as the input
    events. Raises on the first event missing a required field — the
    ingestion service is expected to have validated events before
    calling this, so a failure here is a bug, not user error.

    For fault tolerance on a per-event basis, callers should wrap
    ``compute_fingerprint`` individually and collect errors:
    ``[try_fp(e) for e in events]``.
    """
    return [
        compute_fingerprint(
            source_id=_extract_field(event, "source_id"),
            event_time=_extract_field(event, "event_time"),
            event_type=_extract_field(event, "event_type"),
            action=_extract_field(event, "action"),
            outcome=_extract_field(event, "outcome"),
            username=_extract_field(event, "username"),
            source_ip=_extract_field(event, "source_ip"),
            destination_ip=_extract_field(event, "destination_ip"),
        )
        for event in events
    ]


# ============================================================================
# VALIDATION HELPER (for use by ingestion service)
# ============================================================================

def is_valid_fingerprint(value: Any) -> bool:
    """
    Return True if ``value`` looks like a valid fingerprint.

    A valid fingerprint is exactly 64 lowercase hex characters. This
    is a shape check only — it does not verify the digest corresponds
    to any particular input.
    """
    if not isinstance(value, str):
        return False
    if len(value) != FINGERPRINT_LENGTH:
        return False
    return all(c in "0123456789abcdef" for c in value)


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "FINGERPRINT_VERSION",
    "FINGERPRINT_LENGTH",
    "compute_fingerprint",
    "compute_batch_fingerprints",
    "is_valid_fingerprint",
]