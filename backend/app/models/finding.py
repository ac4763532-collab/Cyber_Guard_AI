"""
CyberGuard AI — Agent Findings Model
============================================================================

The ``agent_findings`` table: the output of the 8 detection agents.

A finding is a structured, auditable claim that one or more security
events match a specific detection rule. It carries:

    - which agent produced it (log_analysis, email_analysis, ...)
    - which rule fired (log.failed_login_burst, email.suspicious_url, ...)
    - how confident the agent is (0.0 to 1.0)
    - how severe the finding is if true (low / medium / high / critical)
    - the events the rule matched (event_ids + primary_event_id)
    - the reasoning / evidence (evidence JSONB — the "why")
    - MITRE ATT&CK technique IDs (optional)
    - a fingerprint for dedup across reruns

Findings are the bridge between raw events (security_events) and
user-facing alerts (security_alerts) and incidents (security_incidents).
Without findings, the platform has no intelligence — just a searchable log.

Design decisions
----------------
1. **Fingerprint dedup across reruns.**
   Same rule + same event(s) + same reasoning = same fingerprint. If an
   agent re-runs a rule (background sweep, incident replay, rule tuning),
   the fingerprint prevents duplicate findings. ``UNIQUE(workspace_id,
   fingerprint)`` enforces this at DB level.

2. **``confidence`` and ``severity`` are orthogonal.**
   ``confidence`` (0.0–1.0) answers: *"how sure are we this is real?"*
   ``severity`` (low/medium/high/critical) answers: *"how bad is it if
   real?"* A rule can be 0.99 confident that something LOW happened, or
   0.40 confident about something possibly CRITICAL. Collapsing them into
   one score would hide important information from investigators.

3. **``agent_name`` + ``rule_id`` composite identifies the rule.**
   Enables per-rule tuning, per-agent analytics, and disabling a specific
   rule without disabling the agent.

4. **``event_ids`` as JSONB array, not a join table.**
   A finding can reference 1 event (``port_scan``) or hundreds
   (``failed_login_burst``). A join table would multiply rows for every
   aggregation finding — bad for the highest-volume relationship. The
   trade-off: no per-event FK integrity. Acceptable because:

       - Findings reference events in the same workspace (service-enforced).
       - Retention of events (90d) is shorter than findings (180d). A
         finding can outlive its events — that is intended.
       - The service validates event IDs at creation time.

5. **``primary_event_id`` FK — one canonical root event.**
   For UI display ("here's the event that triggered this"). For
   aggregation findings, this is the "worst" or "first" event, determined
   by the rule.

6. **``alert_id`` and ``incident_id`` nullable FKs.**
   Findings may be promoted into alerts and swept into incidents. When
   that happens, these FKs link them. When not, findings remain as raw
   agent output — available for analyst review, reporting, and rule tuning.

7. **``mitre_techniques`` JSONB array.** Optional MITRE ATT&CK technique
   IDs (e.g. ``T1110.001`` for brute force). Multiple techniques per
   finding are common.

8. **``status`` lifecycle distinct from severity.**
   A CRITICAL finding can be ``dismissed`` as a false positive; a LOW
   finding can be ``investigating``. Status reflects workflow; severity
   reflects intrinsic risk.

9. **``evidence`` JSONB — the full reasoning.**
   Not just "what happened" but *why we believe it*. Includes the specific
   rule parameters, the matching window, and the field values that
   triggered. This is what makes the finding auditable and defensible.

10. **No ``SoftDeleteMixin``.** Findings are hard-deleted after
    ``RETENTION_FINDINGS_DAYS`` (default 180). False positives are kept
    via ``status = FALSE_POSITIVE``, not deletion — they are tuning data.

Usage
-----
    from app.models import AgentFinding
    from app.models.enums import FindingCategory, FindingStatus, EventSeverity

    finding = AgentFinding.build(
        workspace_id=workspace.id,
        source_id=source.id,
        agent_name="log_analysis",
        rule_id="log.failed_login_burst",
        severity=EventSeverity.HIGH,
        category=FindingCategory.BRUTE_FORCE,
        title="Repeated failed logins from 203.0.113.42",
        description="6 failed login attempts in 40s, exceeding threshold of 5 in 10m.",
        confidence=0.95,
        primary_event_id=first_event.id,
        event_ids=[e.id for e in burst_events],
        evidence={
            "rule_params": {"threshold": 5, "window_seconds": 600},
            "matched_count": 6,
            "source_ip": "203.0.113.42",
            "username": "alice",
        },
        mitre_techniques=["T1110.001"],
        fingerprint=compute_fingerprint(rule_id, event_ids),
    )
    db.add(finding)
    db.commit()
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.core.constants import AGENT_NAMES
from app.core.exceptions import ValidationError
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import (
    EventSeverity,
    FindingCategory,
    FindingStatus,
    enum_column_type,
)


_MAX_AGENT_NAME_LENGTH = 32
_MAX_RULE_ID_LENGTH = 128
_MAX_TITLE_LENGTH = 255
_MAX_DESCRIPTION_LENGTH = 5000
_MAX_FINGERPRINT_LENGTH = 64
_MAX_MITRE_TECHNIQUES = 20
_MAX_EVIDENCE_SIZE_BYTES = 256 * 1024  # 256 KB cap on evidence JSONB
_MAX_EVENT_IDS = 1000
_MAX_TAGS = 20


class AgentFinding(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A detection output produced by one of the platform's 8 security agents.

    One row per distinct finding. Deduplicated by (workspace_id, fingerprint).
    Hard-deleted by the retention service after ``RETENTION_FINDINGS_DAYS``.
    """

    __tablename__ = "agent_findings"

    __table_args__ = (
        # Fingerprint format
        CheckConstraint(
            r"fingerprint ~ '^[a-f0-9]{64}$'",
            name="fingerprint_format",
        ),
        # Confidence in [0.0, 1.0]
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="confidence_range",
        ),
        # Non-negative counters
        CheckConstraint(
            "occurrence_count >= 1",
            name="occurrence_count_positive",
        ),
        # Dedup: unique per (workspace, fingerprint).
        Index(
            "uq_findings_workspace_fingerprint",
            "workspace_id",
            "fingerprint",
            unique=True,
        ),
        # Main dashboard query: recent findings in a workspace.
        Index(
            "ix_findings_workspace_created",
            "workspace_id",
            "created_at",
        ),
        # Filter by severity (dashboard severity tabs).
        Index(
            "ix_findings_workspace_severity_created",
            "workspace_id",
            "severity",
            "created_at",
        ),
        # Filter by status (open / investigating / resolved tabs).
        Index(
            "ix_findings_workspace_status_created",
            "workspace_id",
            "status",
            "created_at",
        ),
        # Per-agent analytics.
        Index(
            "ix_findings_agent_created",
            "agent_name",
            "created_at",
        ),
        # Per-rule tuning.
        Index(
            "ix_findings_rule_created",
            "agent_name",
            "rule_id",
            "created_at",
        ),
        # Alert and incident linkage queries.
        Index(
            "ix_findings_alert_id",
            "alert_id",
        ),
        Index(
            "ix_findings_incident_id",
            "incident_id",
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Tenant & source
    # ────────────────────────────────────────────────────────────────────

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Tenant boundary. Deleting the workspace cascades its findings.",
    )

    source_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("security_sources.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment=(
            "Source that produced the primary event. NULL for cross-source "
            "correlation findings, or after the source is hard-deleted."
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Agent & rule identity
    # ────────────────────────────────────────────────────────────────────

    agent_name: Mapped[str] = mapped_column(
        String(_MAX_AGENT_NAME_LENGTH),
        nullable=False,
        index=True,
        comment=(
            "Which agent produced this finding. One of: email_analysis, "
            "log_analysis, network_analysis, ai_analyst, "
            "threat_intelligence, ioc_correlation, incident_response, "
            "reporting."
        ),
    )

    rule_id: Mapped[str] = mapped_column(
        String(_MAX_RULE_ID_LENGTH),
        nullable=False,
        comment=(
            "Identifier of the specific detection rule that fired "
            "(e.g. 'log.failed_login_burst', 'email.suspicious_url')."
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Classification
    # ────────────────────────────────────────────────────────────────────

    severity: Mapped[EventSeverity] = mapped_column(
        enum_column_type(EventSeverity),
        nullable=False,
        default=EventSeverity.MEDIUM,
        server_default=EventSeverity.MEDIUM.value,
        index=True,
        comment="How bad is it if real (low / medium / high / critical).",
    )

    category: Mapped[FindingCategory] = mapped_column(
        enum_column_type(FindingCategory),
        nullable=False,
        default=FindingCategory.OTHER,
        server_default=FindingCategory.OTHER.value,
        index=True,
        comment="What kind of threat this finding represents.",
    )

    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.5,
        server_default="0.5",
        comment=(
            "How confident the agent is that this is a true positive (0.0–1.0). "
            "Distinct from severity: a rule can be very confident about a "
            "low-severity event, or uncertain about a possible critical one."
        ),
    )

    status: Mapped[FindingStatus] = mapped_column(
        enum_column_type(FindingStatus),
        nullable=False,
        default=FindingStatus.NEW,
        server_default=FindingStatus.NEW.value,
        index=True,
        comment=(
            "Workflow state: new, acknowledged, investigating, resolved, "
            "dismissed, false_positive."
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Presentation
    # ────────────────────────────────────────────────────────────────────

    title: Mapped[str] = mapped_column(
        String(_MAX_TITLE_LENGTH),
        nullable=False,
        comment="One-line summary shown in dashboards and alerts.",
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Longer narrative from the agent — what was detected and why.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Event references
    # ────────────────────────────────────────────────────────────────────

    primary_event_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("security_events.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment=(
            "The canonical 'root' event for this finding. For aggregation "
            "findings, the worst or first event per the rule definition."
        ),
    )

    event_ids: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment=(
            "Array of event UUIDs (as strings) this finding references. "
            "Not a FK — see design notes. Enables one finding to aggregate "
            "many events."
        ),
    )

    occurrence_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default="1",
        comment=(
            "How many times this finding has re-fired (deduplicated by "
            "fingerprint). A brute-force finding that persists for hours "
            "increments this with each new batch."
        ),
    )

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=func.now(),
        server_default=func.now(),
        comment="When this finding was first created. Preserved across dedup merges.",
    )

    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=func.now(),
        server_default=func.now(),
        comment="When this finding last re-fired. Updated on dedup merges.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Deduplication
    # ────────────────────────────────────────────────────────────────────

    fingerprint: Mapped[str] = mapped_column(
        String(_MAX_FINGERPRINT_LENGTH),
        nullable=False,
        comment=(
            "SHA-256 hex of (agent_name || rule_id || sorted(event_ids) || "
            "key evidence fields). Same reasoning = same fingerprint. "
            "Unique per workspace."
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Evidence & enrichment
    # ────────────────────────────────────────────────────────────────────

    evidence: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
        comment=(
            "Structured reasoning: rule parameters, matched field values, "
            "counts, thresholds. The 'why' behind the finding."
        ),
    )

    mitre_techniques: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment=(
            "MITRE ATT&CK technique IDs (e.g. ['T1110.001', 'T1078']). "
            "Optional enrichment for analyst understanding."
        ),
    )

    tags: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment="Free-form tags for filtering and correlation.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Promotion links (finding → alert → incident)
    # ────────────────────────────────────────────────────────────────────

    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("security_alerts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Alert this finding was promoted into. NULL until promoted.",
    )

    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("security_incidents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Incident this finding was swept into by the correlation agent.",
    )

    # ====================================================================
    # VALIDATORS
    # ====================================================================

    @validates("agent_name")
    def _validate_agent_name(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="agent_name must be a string",
                code="FINDING_AGENT_INVALID_TYPE",
            )
        normalized = value.strip().lower()
        if normalized not in AGENT_NAMES:
            raise ValidationError(
                message=f"agent_name must be one of {list(AGENT_NAMES)}",
                code="FINDING_AGENT_INVALID",
                details={
                    "received": value,
                    "allowed": list(AGENT_NAMES),
                },
            )
        return normalized

    @validates("rule_id")
    def _validate_rule_id(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="rule_id must be a string",
                code="FINDING_RULE_INVALID_TYPE",
            )
        stripped = value.strip()
        if not stripped:
            raise ValidationError(
                message="rule_id must not be empty",
                code="FINDING_RULE_EMPTY",
            )
        if len(stripped) > _MAX_RULE_ID_LENGTH:
            raise ValidationError(
                message=f"rule_id must not exceed {_MAX_RULE_ID_LENGTH} characters",
                code="FINDING_RULE_TOO_LONG",
            )
        return stripped

    @validates("title")
    def _validate_title(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="title must be a string",
                code="FINDING_TITLE_INVALID_TYPE",
            )
        stripped = value.strip()
        if not stripped:
            raise ValidationError(
                message="title must not be empty",
                code="FINDING_TITLE_EMPTY",
            )
        if len(stripped) > _MAX_TITLE_LENGTH:
            raise ValidationError(
                message=f"title must not exceed {_MAX_TITLE_LENGTH} characters",
                code="FINDING_TITLE_TOO_LONG",
            )
        return stripped

    @validates("confidence")
    def _validate_confidence(self, _key: str, value: float) -> float:
        try:
            f = float(value)
        except (TypeError, ValueError) as exc:
            raise ValidationError(
                message="confidence must be a number",
                code="FINDING_CONFIDENCE_INVALID_TYPE",
            ) from exc
        if not (0.0 <= f <= 1.0):
            raise ValidationError(
                message="confidence must be between 0.0 and 1.0",
                code="FINDING_CONFIDENCE_OUT_OF_RANGE",
                details={"received": f},
            )
        return f

    @validates("fingerprint")
    def _validate_fingerprint(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="fingerprint must be a string",
                code="FINDING_FINGERPRINT_INVALID_TYPE",
            )
        normalized = value.strip().lower()
        if len(normalized) != 64 or not all(c in "0123456789abcdef" for c in normalized):
            raise ValidationError(
                message="fingerprint must be 64 lowercase hex characters",
                code="FINDING_FINGERPRINT_INVALID_FORMAT",
            )
        return normalized

    @validates("event_ids")
    def _validate_event_ids(self, _key: str, value: list[str] | None) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValidationError(
                message="event_ids must be a list of strings",
                code="FINDING_EVENT_IDS_INVALID_TYPE",
            )
        if len(value) > _MAX_EVENT_IDS:
            raise ValidationError(
                message=f"event_ids must not exceed {_MAX_EVENT_IDS} items",
                code="FINDING_EVENT_IDS_TOO_MANY",
            )
        cleaned: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise ValidationError(
                    message="each event_id must be a string",
                    code="FINDING_EVENT_ID_INVALID_TYPE",
                )
            cleaned.append(item.strip())
        return cleaned

    @validates("mitre_techniques")
    def _validate_mitre_techniques(
        self, _key: str, value: list[str] | None
    ) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValidationError(
                message="mitre_techniques must be a list of strings",
                code="FINDING_MITRE_INVALID_TYPE",
            )
        if len(value) > _MAX_MITRE_TECHNIQUES:
            raise ValidationError(
                message=f"mitre_techniques must not exceed {_MAX_MITRE_TECHNIQUES} items",
                code="FINDING_MITRE_TOO_MANY",
            )
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, str):
                raise ValidationError(
                    message="each MITRE technique must be a string",
                    code="FINDING_MITRE_ITEM_INVALID_TYPE",
                )
            stripped = item.strip().upper()
            if not stripped or stripped in seen:
                continue
            seen.add(stripped)
            cleaned.append(stripped)
        return cleaned

    @validates("tags")
    def _validate_tags(self, _key: str, value: list[str] | None) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValidationError(
                message="tags must be a list of strings",
                code="FINDING_TAGS_INVALID_TYPE",
            )
        if len(value) > _MAX_TAGS:
            raise ValidationError(
                message=f"tags must not exceed {_MAX_TAGS} items",
                code="FINDING_TAGS_TOO_MANY",
            )
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, str):
                raise ValidationError(
                    message="each tag must be a string",
                    code="FINDING_TAG_INVALID_TYPE",
                )
            stripped = item.strip().lower()
            if not stripped or stripped in seen:
                continue
            if len(stripped) > 64:
                raise ValidationError(
                    message="each tag must not exceed 64 characters",
                    code="FINDING_TAG_TOO_LONG",
                )
            seen.add(stripped)
            cleaned.append(stripped)
        return cleaned

    @validates("severity")
    def _validate_severity(
        self, _key: str, value: EventSeverity | str
    ) -> EventSeverity:
        if isinstance(value, EventSeverity):
            return value
        if isinstance(value, str):
            try:
                return EventSeverity(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid severity {value!r}",
                    code="FINDING_SEVERITY_INVALID",
                    details={"allowed": list(EventSeverity.values())},
                ) from exc
        raise ValidationError(
            message="severity must be an EventSeverity or string",
            code="FINDING_SEVERITY_INVALID_TYPE",
        )

    @validates("category")
    def _validate_category(
        self, _key: str, value: FindingCategory | str
    ) -> FindingCategory:
        if isinstance(value, FindingCategory):
            return value
        if isinstance(value, str):
            try:
                return FindingCategory(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid category {value!r}",
                    code="FINDING_CATEGORY_INVALID",
                    details={"allowed": list(FindingCategory.values())},
                ) from exc
        raise ValidationError(
            message="category must be a FindingCategory or string",
            code="FINDING_CATEGORY_INVALID_TYPE",
        )

    @validates("status")
    def _validate_status(
        self, _key: str, value: FindingStatus | str
    ) -> FindingStatus:
        if isinstance(value, FindingStatus):
            return value
        if isinstance(value, str):
            try:
                return FindingStatus(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid status {value!r}",
                    code="FINDING_STATUS_INVALID",
                    details={"allowed": list(FindingStatus.values())},
                ) from exc
        raise ValidationError(
            message="status must be a FindingStatus or string",
            code="FINDING_STATUS_INVALID_TYPE",
        )

    # ====================================================================
    # CONSTRUCTION HELPER
    # ====================================================================

    @classmethod
    def build(
        cls,
        *,
        workspace_id: uuid.UUID,
        agent_name: str,
        rule_id: str,
        title: str,
        fingerprint: str,
        severity: EventSeverity = EventSeverity.MEDIUM,
        category: FindingCategory = FindingCategory.OTHER,
        confidence: float = 0.5,
        description: str | None = None,
        source_id: uuid.UUID | None = None,
        primary_event_id: uuid.UUID | None = None,
        event_ids: list[str] | None = None,
        evidence: dict[str, Any] | None = None,
        mitre_techniques: list[str] | None = None,
        tags: list[str] | None = None,
        status: FindingStatus = FindingStatus.NEW,
    ) -> "AgentFinding":
        """
        Construct a new finding.

        The caller is responsible for computing ``fingerprint`` — the
        canonical way is via ``app.services.event_fingerprint``. The
        fingerprint must be deterministic across reruns of the same rule
        against the same events, or dedup will not work.
        """
        now = datetime.now(__import__("datetime").timezone.utc)
        return cls(
            workspace_id=workspace_id,
            source_id=source_id,
            agent_name=agent_name,
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            category=category,
            confidence=confidence,
            status=status,
            primary_event_id=primary_event_id,
            event_ids=event_ids or [],
            evidence=evidence or {},
            mitre_techniques=mitre_techniques or [],
            tags=tags or [],
            fingerprint=fingerprint,
            occurrence_count=1,
            first_seen_at=now,
            last_seen_at=now,
        )

    # ====================================================================
    # LIFECYCLE METHODS
    # ====================================================================

    def record_recurrence(self, new_event_ids: list[str] | None = None) -> None:
        """
        Increment ``occurrence_count``, bump ``last_seen_at``, and merge
        new event IDs. Called when a rule re-fires and the fingerprint
        matches an existing finding.
        """
        self.occurrence_count += 1
        self.last_seen_at = datetime.now(__import__("datetime").timezone.utc)
        if new_event_ids:
            existing = set(self.event_ids or [])
            merged = list(existing.union(new_event_ids))
            # Cap at _MAX_EVENT_IDS to prevent runaway growth
            self.event_ids = merged[-_MAX_EVENT_IDS:]

    def acknowledge(self) -> None:
        """Transition to ACKNOWLEDGED. Idempotent."""
        if self.status == FindingStatus.NEW:
            self.status = FindingStatus.ACKNOWLEDGED

    def mark_investigating(self) -> None:
        """Transition to INVESTIGATING. Idempotent."""
        if self.status in (FindingStatus.NEW, FindingStatus.ACKNOWLEDGED):
            self.status = FindingStatus.INVESTIGATING

    def resolve(self) -> None:
        """Mark as RESOLVED (investigated and addressed)."""
        self.status = FindingStatus.RESOLVED

    def dismiss(self) -> None:
        """Mark as DISMISSED (not actionable, but not confirmed false)."""
        self.status = FindingStatus.DISMISSED

    def mark_false_positive(self) -> None:
        """Mark as FALSE_POSITIVE (rule tuning data)."""
        self.status = FindingStatus.FALSE_POSITIVE

    # ====================================================================
    # STATE PROPERTIES
    # ====================================================================

    @property
    def is_open(self) -> bool:
        """True if this finding is still in an active workflow state."""
        return self.status in (
            FindingStatus.NEW,
            FindingStatus.ACKNOWLEDGED,
            FindingStatus.INVESTIGATING,
        )

    @property
    def is_closed(self) -> bool:
        """True if this finding is resolved, dismissed, or a false positive."""
        return self.status in (
            FindingStatus.RESOLVED,
            FindingStatus.DISMISSED,
            FindingStatus.FALSE_POSITIVE,
        )

    @property
    def is_promoted_to_alert(self) -> bool:
        """True if this finding has been promoted into an alert."""
        return self.alert_id is not None

    @property
    def is_linked_to_incident(self) -> bool:
        """True if this finding has been swept into an incident."""
        return self.incident_id is not None

    @property
    def is_high_or_critical(self) -> bool:
        """True if severity is HIGH or CRITICAL."""
        return self.severity in (EventSeverity.HIGH, EventSeverity.CRITICAL)

    @property
    def is_high_confidence(self, threshold: float = 0.75) -> bool:
        """True if confidence is at or above the given threshold."""
        return self.confidence >= threshold

    @property
    def age_seconds(self) -> int:
        """Seconds since this finding was first seen."""
        first = self.first_seen_at
        if first.tzinfo is None:
            first = first.replace(tzinfo=__import__("datetime").timezone.utc)
        delta = datetime.now(__import__("datetime").timezone.utc) - first
        return int(delta.total_seconds())


# ============================================================================
# RELATIONSHIPS (added incrementally as child models land)
# ============================================================================
# from sqlalchemy.orm import relationship
# from typing import TYPE_CHECKING
#
# if TYPE_CHECKING:
#     from app.models.workspace import Workspace
#     from app.models.source import SecuritySource
#     from app.models.event import SecurityEvent
#     from app.models.alert import SecurityAlert
#     from app.models.incident import SecurityIncident
#
# class AgentFinding(...):
#     ...
#     workspace: Mapped["Workspace"] = relationship(
#         "Workspace", back_populates="findings"
#     )
#     source: Mapped["SecuritySource | None"] = relationship(
#         "SecuritySource"
#     )
#     primary_event: Mapped["SecurityEvent | None"] = relationship(
#         "SecurityEvent",
#         foreign_keys=[primary_event_id],
#     )
#     alert: Mapped["SecurityAlert | None"] = relationship(
#         "SecurityAlert",
#         back_populates="findings",
#     )
#     incident: Mapped["SecurityIncident | None"] = relationship(
#         "SecurityIncident",
#         back_populates="findings",
#     )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "AgentFinding",
    "_MAX_AGENT_NAME_LENGTH",
    "_MAX_RULE_ID_LENGTH",
    "_MAX_TITLE_LENGTH",
    "_MAX_DESCRIPTION_LENGTH",
    "_MAX_FINGERPRINT_LENGTH",
    "_MAX_MITRE_TECHNIQUES",
    "_MAX_EVIDENCE_SIZE_BYTES",
    "_MAX_EVENT_IDS",
    "_MAX_TAGS",
]