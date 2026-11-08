"""
CyberGuard AI — Collector Installation Records
============================================================================

The ``collector_credentials`` table: a lifecycle record for each physical
collector installation, distinct from the auth tokens (``source_credentials``)
used per-request.

Why this table exists
---------------------
A collector installation on a device (say, Priya's laptop) lives for months
or years. During its lifetime it:

    - authenticates on every event-ingestion request
    - rotates its auth token every ``COLLECTOR_CREDENTIAL_ROTATION_DAYS``
    - receives heartbeats every ``COLLECTOR_HEARTBEAT_INTERVAL_SECONDS``
    - may be reinstalled (same hardware, new installation)
    - may be retired or revoked at any time

``source_credentials`` (File 21) models the *auth token* — one row per
token. Rotate 12 times a year → 12 rows over the year.

``collector_credentials`` (this file) models the *installation* — one row
per physical installation. Same 12 rotations → still 1 row, with
``rotation_count = 12``.

Both tables reference the same ``source_id``. The service layer correlates
them via ``(source_id, timestamps)`` when needed.

Design decisions
----------------
1. **1:N with ``source_id``.** A source can be reinstalled (reimage, HW
   swap) — each installation gets its own row, and ``(source_id,
   collector_id)`` is unique.

2. **``collector_id`` is stable across rotations and re-enrollments.**
   Assigned by the collector on first install and persisted to disk
   (``%PROGRAMDATA%\\CyberGuard\\collector_id`` on Windows,
   ``/etc/cyberguard/collector_id`` on Linux). Survives token rotation and
   even re-enrollment on the same device. This lets the platform:

       - match incoming requests to a specific installation
       - detect re-enrollment (same collector_id, new installation record)
       - correlate heartbeats across credential rotations

3. **``hardware_fingerprint`` separate from ``collector_id``.**
   ``collector_id`` is a UUID chosen by the collector (which a malicious
   collector could regenerate). ``hardware_fingerprint`` is a hash of the
   physical device (CPU + disk + MAC) that does *not* change on reinstall.
   Used by the future anti-spoofing check: "same source, same hardware,
   different collector_id" is suspicious.

4. **Status: active / retired / revoked.**

       active   — currently accepting events and heartbeats
       retired  — superseded by a newer installation on the same device
       revoked  — explicitly terminated for security

   ``retired`` and ``revoked`` differ in intent. ``retired`` = "we replaced
   it ourselves". ``revoked`` = "someone decided this was dangerous".

5. **Two auth timestamps.**

       last_auth_at        — a token was successfully validated
       last_heartbeat_at   — the process checked in

   A heartbeat without auth means a misconfigured collector. Auth without
   heartbeat means an event was accepted but no periodic "I'm alive" — both
   are signals worth surfacing separately in the health UI.

6. **``rotation_count`` incremented by the rotation service.** Enables
   auditing suspicious patterns: "47 rotations in 3 months" is worth
   investigating.

7. **No ``SoftDeleteMixin``.** Status + ``retired_at`` / ``revoked_at``
   encode lifecycle completely. A soft-deleted installation would be an
   installation that's neither active nor retired nor revoked — that's
   not a state we recognize.

8. **``ON DELETE CASCADE`` on ``source_id``.** A deleted source's
   installations are dead weight. The audit log is the source of truth for
   history; orgs that need to retain installation history should disable
   the source, not delete it.

Usage
-----
    from app.models import CollectorCredential

    # At enrollment time
    installation = CollectorCredential.build(
        source_id=source.id,
        collector_id=collector_uuid_from_device,
        hostname="priya-laptop",
        os_version="Windows 11 23H2",
        hardware_fingerprint="sha256:...",
        installation_metadata={
            "installer_version": "1.0.3",
            "install_path": "C:\\Program Files\\CyberGuard",
            "tamper_protection": True,
        },
    )
    db.add(installation)
    db.commit()

    # On heartbeat
    installation.record_heartbeat(from_ip="203.0.113.42")

    # On successful auth
    installation.record_auth()

    # On rotation
    installation.rotation_count += 1

    # On explicit termination
    installation.revoke(by_admin_id=admin.id, reason="Device sold")
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.core.exceptions import ValidationError
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


#: Installation status values. Enforced at ORM level and by CHECK constraint.
_STATUS_ACTIVE = "active"
_STATUS_RETIRED = "retired"
_STATUS_REVOKED = "revoked"
_VALID_STATUSES = frozenset({_STATUS_ACTIVE, _STATUS_RETIRED, _STATUS_REVOKED})

#: Hardware fingerprint format: ``sha256:<64 lowercase hex>``.
_HW_FINGERPRINT_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")

_MAX_HOSTNAME_LENGTH = 255
_MAX_OS_VERSION_LENGTH = 64
_MAX_IP_ADDRESS_LENGTH = 45
_MAX_INSTALLER_VERSION_LENGTH = 32
_MAX_REVOCATION_REASON_LENGTH = 500
_MAX_RETIREMENT_REASON_LENGTH = 500
_MAX_INSTALLATION_METADATA_SIZE = 64 * 1024  # 64 KB cap on JSONB


class CollectorCredential(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A specific physical collector installation on a device.

    One row per installation. Auth tokens live in ``source_credentials``
    (File 21) and reference the same ``source_id``. This table tracks the
    installation's lifecycle: enrollment, heartbeats, auth, rotations,
    retirement, revocation.
    """

    __tablename__ = "collector_credentials"

    __table_args__ = (
        # Status must be one of the documented values.
        CheckConstraint(
            "status IN ('active', 'retired', 'revoked')",
            name="status_values",
        ),
        # Retired/revoked require a timestamp.
        CheckConstraint(
            "status <> 'retired' OR retired_at IS NOT NULL",
            name="retired_requires_timestamp",
        ),
        CheckConstraint(
            "status <> 'revoked' OR revoked_at IS NOT NULL",
            name="revoked_requires_timestamp",
        ),
        # Rotation count must be non-negative.
        CheckConstraint(
            "rotation_count >= 0",
            name="rotation_count_non_negative",
        ),
        # Hardware fingerprint format, or NULL for legacy installs.
        CheckConstraint(
            "hardware_fingerprint IS NULL OR "
            r"hardware_fingerprint ~ '^sha256:[a-f0-9]{64}$'",
            name="hardware_fingerprint_format",
        ),
        # Same collector_id cannot appear twice for the same source.
        UniqueConstraint(
            "source_id",
            "collector_id",
            name="uq_source_collector",
        ),
        # Frequent queries:
        Index(
            "ix_collector_credentials_source_status",
            "source_id",
            "status",
        ),
        Index(
            "ix_collector_credentials_last_heartbeat",
            "last_heartbeat_at",
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Bindings
    # ────────────────────────────────────────────────────────────────────

    source_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("security_sources.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Owning source. Deleting the source cascades installation records.",
    )

    collector_id: Mapped[uuid.UUID] = mapped_column(
        nullable=False,
        index=True,
        comment=(
            "UUID assigned by the collector on first install, persisted to disk "
            "(ProgramData on Windows, /etc on Linux). Stable across rotations."
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Device identity
    # ────────────────────────────────────────────────────────────────────

    hostname: Mapped[str | None] = mapped_column(
        String(_MAX_HOSTNAME_LENGTH),
        nullable=True,
        comment="Hostname reported by the collector at enrollment.",
    )

    os_version: Mapped[str | None] = mapped_column(
        String(_MAX_OS_VERSION_LENGTH),
        nullable=True,
        comment="OS version reported by the collector at enrollment.",
    )

    hardware_fingerprint: Mapped[str | None] = mapped_column(
        String(80),
        nullable=True,
        index=True,
        comment=(
            "Stable hash of physical device (CPU + disk + MAC), format "
            "'sha256:<64 hex>'. Used by anti-spoofing to detect "
            "device-level anomalies across reinstallations."
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Status
    # ────────────────────────────────────────────────────────────────────

    status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=_STATUS_ACTIVE,
        server_default=_STATUS_ACTIVE,
        index=True,
        comment="Lifecycle: active, retired, revoked.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Lifecycle timestamps
    # ────────────────────────────────────────────────────────────────────

    enrolled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        comment="When this installation was first enrolled.",
    )

    last_heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Most recent heartbeat received from this installation.",
    )

    last_auth_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Most recent successful authentication using any credential.",
    )

    last_seen_ip: Mapped[str | None] = mapped_column(
        String(_MAX_IP_ADDRESS_LENGTH),
        nullable=True,
        comment="Last source IP observed from this installation (heartbeat or auth).",
    )

    retired_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When this installation was retired (superseded by a newer one).",
    )

    retirement_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Free-text reason for retirement (e.g. 'device reimaged').",
    )

    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When this installation was explicitly revoked for security.",
    )

    revoked_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User who revoked this installation. NULL after user hard-delete.",
    )

    revocation_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Reason recorded when this installation was revoked.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Rotation tracking
    # ────────────────────────────────────────────────────────────────────

    rotation_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        comment="Number of times the underlying auth token has been rotated.",
    )

    last_rotated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the auth token was last rotated.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Installation metadata
    # ────────────────────────────────────────────────────────────────────

    installer_version: Mapped[str | None] = mapped_column(
        String(_MAX_INSTALLER_VERSION_LENGTH),
        nullable=True,
        comment="Version of the installer that created this installation.",
    )

    installation_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
        comment=(
            "Installation context: {install_path, installer_version, "
            "tamper_protection_enabled, ...}. Shape validated by the service."
        ),
    )

    # ====================================================================
    # VALIDATORS
    # ====================================================================

    @validates("status")
    def _validate_status(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="status must be a string",
                code="COLLECTOR_STATUS_INVALID_TYPE",
            )
        normalized = value.strip().lower()
        if normalized not in _VALID_STATUSES:
            raise ValidationError(
                message=(
                    f"status must be one of {sorted(_VALID_STATUSES)}"
                ),
                code="COLLECTOR_STATUS_INVALID",
                details={
                    "received": value,
                    "allowed": sorted(_VALID_STATUSES),
                },
            )
        return normalized

    @validates("hardware_fingerprint")
    def _validate_hardware_fingerprint(
        self, _key: str, value: str | None
    ) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValidationError(
                message="hardware_fingerprint must be a string or None",
                code="COLLECTOR_HW_FP_INVALID_TYPE",
            )
        stripped = value.strip().lower()
        if not _HW_FINGERPRINT_PATTERN.match(stripped):
            raise ValidationError(
                message=(
                    "hardware_fingerprint must match the format "
                    "'sha256:<64 lowercase hex chars>'"
                ),
                code="COLLECTOR_HW_FP_INVALID_FORMAT",
                details={"received": value[:20] + "..." if len(value) > 20 else value},
            )
        return stripped

    @validates("hostname")
    def _validate_hostname(self, _key: str, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValidationError(
                message="hostname must be a string or None",
                code="COLLECTOR_HOSTNAME_INVALID_TYPE",
            )
        stripped = value.strip()
        if not stripped:
            return None
        if len(stripped) > _MAX_HOSTNAME_LENGTH:
            raise ValidationError(
                message=f"hostname must not exceed {_MAX_HOSTNAME_LENGTH} characters",
                code="COLLECTOR_HOSTNAME_TOO_LONG",
            )
        return stripped

    @validates("retirement_reason", "revocation_reason")
    def _validate_reason(self, key: str, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValidationError(
                message=f"{key} must be a string or None",
                code="COLLECTOR_REASON_INVALID_TYPE",
            )
        stripped = value.strip()
        if not stripped:
            return None
        max_len = (
            _MAX_RETIREMENT_REASON_LENGTH
            if key == "retirement_reason"
            else _MAX_REVOCATION_REASON_LENGTH
        )
        if len(stripped) > max_len:
            raise ValidationError(
                message=f"{key} must not exceed {max_len} characters",
                code="COLLECTOR_REASON_TOO_LONG",
            )
        return stripped

    @validates("installation_metadata")
    def _validate_installation_metadata(
        self, _key: str, value: dict[str, Any] | None
    ) -> dict[str, Any]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ValidationError(
                message="installation_metadata must be a dict",
                code="COLLECTOR_META_INVALID_TYPE",
            )
        return value

    # ====================================================================
    # CONSTRUCTION HELPER
    # ====================================================================

    @classmethod
    def build(
        cls,
        *,
        source_id: uuid.UUID,
        collector_id: uuid.UUID,
        hostname: str | None = None,
        os_version: str | None = None,
        hardware_fingerprint: str | None = None,
        installer_version: str | None = None,
        installation_metadata: dict[str, Any] | None = None,
    ) -> "CollectorCredential":
        """
        Construct a new installation record in the ``active`` state.

        Called at the moment a collector successfully enrolls (after the
        enrollment token is validated). The ``collector_id`` should come
        from the enrollment request payload — it is the collector's
        self-assigned identifier, persisted to disk on the device.
        """
        return cls(
            source_id=source_id,
            collector_id=collector_id,
            hostname=hostname,
            os_version=os_version,
            hardware_fingerprint=hardware_fingerprint,
            installer_version=installer_version,
            installation_metadata=installation_metadata or {},
            status=_STATUS_ACTIVE,
            enrolled_at=datetime.now(timezone.utc),
        )

    # ====================================================================
    # LIFECYCLE METHODS
    # ====================================================================

    def record_heartbeat(self, from_ip: str | None = None) -> None:
        """
        Update heartbeat timestamp. Called by the heartbeat service on every
        heartbeat received for this installation.
        """
        now = datetime.now(timezone.utc)
        self.last_heartbeat_at = now
        if from_ip:
            self.last_seen_ip = from_ip.strip()

    def record_auth(self, from_ip: str | None = None) -> None:
        """
        Update auth timestamp. Called by the ingestion service on every
        successful credential verification.
        """
        now = datetime.now(timezone.utc)
        self.last_auth_at = now
        if from_ip:
            self.last_seen_ip = from_ip.strip()

    def record_rotation(self) -> None:
        """
        Increment rotation counter. Called by the rotation service.
        """
        self.rotation_count += 1
        self.last_rotated_at = datetime.now(timezone.utc)

    def retire(self, reason: str | None = None) -> None:
        """
        Mark this installation as retired (superseded by a newer one).

        Only valid from ``active``. Idempotent if already retired.
        """
        if self.status == _STATUS_RETIRED:
            return
        if self.status == _STATUS_REVOKED:
            raise ValidationError(
                message="Cannot retire a revoked installation",
                code="COLLECTOR_CANNOT_RETIRE_REVOKED",
            )
        self.status = _STATUS_RETIRED
        self.retired_at = datetime.now(timezone.utc)
        if reason:
            self.retirement_reason = reason

    def revoke(
        self,
        *,
        by_user_id: uuid.UUID | None = None,
        reason: str | None = None,
    ) -> None:
        """
        Mark this installation as revoked for security. Terminal state.

        Idempotent if already revoked. Cannot be undone — use a new
        installation record if the same physical device needs to re-enroll.
        """
        if self.status == _STATUS_REVOKED:
            return
        self.status = _STATUS_REVOKED
        self.revoked_at = datetime.now(timezone.utc)
        if by_user_id is not None:
            self.revoked_by_id = by_user_id
        if reason:
            self.revocation_reason = reason

    # ====================================================================
    # STATE PROPERTIES
    # ====================================================================

    @property
    def is_active(self) -> bool:
        """True if this installation is currently accepting traffic."""
        return self.status == _STATUS_ACTIVE

    @property
    def is_retired(self) -> bool:
        """True if this installation has been superseded."""
        return self.status == _STATUS_RETIRED

    @property
    def is_revoked(self) -> bool:
        """True if this installation was terminated for security."""
        return self.status == _STATUS_REVOKED

    @property
    def is_stale(self, threshold_seconds: int = 300) -> bool:
        """
        True if ``last_heartbeat_at`` is older than ``threshold_seconds``.

        Default 300s matches ``COLLECTOR_STALE_AFTER_SECONDS``. For custom
        thresholds use ``seconds_since_heartbeat``.
        """
        if self.last_heartbeat_at is None:
            return True
        last = self.last_heartbeat_at
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        elapsed = (datetime.now(timezone.utc) - last).total_seconds()
        return elapsed > threshold_seconds

    @property
    def seconds_since_heartbeat(self) -> int | None:
        """Seconds since last heartbeat, or ``None`` if never received."""
        if self.last_heartbeat_at is None:
            return None
        last = self.last_heartbeat_at
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        return int((datetime.now(timezone.utc) - last).total_seconds())

    @property
    def seconds_since_auth(self) -> int | None:
        """Seconds since last successful auth, or ``None`` if never."""
        if self.last_auth_at is None:
            return None
        last = self.last_auth_at
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        return int((datetime.now(timezone.utc) - last).total_seconds())

    @property
    def age_days(self) -> int:
        """Days since this installation was enrolled."""
        enrolled = self.enrolled_at
        if enrolled.tzinfo is None:
            enrolled = enrolled.replace(tzinfo=timezone.utc)
        return int((datetime.now(timezone.utc) - enrolled).total_seconds() / 86400)


# ============================================================================
# RELATIONSHIPS (added incrementally as child models land)
# ============================================================================
# from sqlalchemy.orm import relationship
# from typing import TYPE_CHECKING
#
# if TYPE_CHECKING:
#     from app.models.source import SecuritySource
#     from app.models.user import User
#
# class CollectorCredential(...):
#     ...
#     source: Mapped["SecuritySource"] = relationship(
#         "SecuritySource",
#         back_populates="collector_installations",
#     )
#     revoked_by: Mapped["User | None"] = relationship(
#         "User",
#         foreign_keys=[revoked_by_id],
#     )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "CollectorCredential",
    "_STATUS_ACTIVE",
    "_STATUS_RETIRED",
    "_STATUS_REVOKED",
    "_VALID_STATUSES",
    "_HW_FINGERPRINT_PATTERN",
    "_MAX_HOSTNAME_LENGTH",
    "_MAX_OS_VERSION_LENGTH",
    "_MAX_IP_ADDRESS_LENGTH",
    "_MAX_INSTALLER_VERSION_LENGTH",
    "_MAX_REVOCATION_REASON_LENGTH",
    "_MAX_RETIREMENT_REASON_LENGTH",
    "_MAX_INSTALLATION_METADATA_SIZE",
]