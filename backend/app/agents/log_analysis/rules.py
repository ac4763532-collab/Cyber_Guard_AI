"""
CyberGuard AI — Log Analysis Detection Rules
============================================================================

Five deterministic detection rules for the Log Analysis Agent.

Rule interface
--------------
Every rule inherits ``BaseRule`` and implements:

    evaluate(context: AgentContext) -> FindingSpec | None

Returning None means "this rule doesn't apply to this event" — the fast
path for the common case. Returning a ``FindingSpec`` means "the rule
matched; here's what to record."

Rules are stateless — no instance state between events. Config is
passed at construction time. This makes them trivially testable:
construct the rule, build a context, call ``evaluate()``, assert on
the result.

The 5 rules
-----------
    1. FailedLoginBurstRule         (log.failed_login_burst)
    2. PrivilegeEscalationRule      (log.privilege_escalation)
    3. AccountModificationRule      (log.account_modification)
    4. SuspiciousFileAccessRule     (log.suspicious_file_access)
    5. UnusualLoginRule             (log.unusual_login)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select

from app.agents.base import AgentContext
from app.models.enums import (
    EventCategory,
    EventSeverity,
    FindingCategory,
)
from app.models.event import SecurityEvent


# ============================================================================
# FINDING SPEC
# ============================================================================

@dataclass(frozen=True)
class FindingSpec:
    """
    A rule's detection result. The agent passes these to
    ``BaseAgent._make_finding`` which persists them.

    All fields except ``event_ids`` have sensible defaults, so rules
    only populate what's relevant.
    """
    rule_id: str
    title: str
    severity: EventSeverity
    category: FindingCategory
    confidence: float
    event_ids: list[uuid.UUID]
    evidence: dict[str, Any] = field(default_factory=dict)
    description: str | None = None
    primary_event_id: uuid.UUID | None = None
    mitre_techniques: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    dedup_hint: str | None = None

    def as_kwargs(self) -> dict[str, Any]:
        """Convert to the kwargs expected by ``BaseAgent._make_finding``."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "confidence": self.confidence,
            "event_ids": self.event_ids,
            "evidence": self.evidence,
            "description": self.description,
            "primary_event_id": self.primary_event_id,
            "mitre_techniques": self.mitre_techniques,
            "tags": self.tags,
            "dedup_hint": self.dedup_hint,
        }


# ============================================================================
# BASE RULE
# ============================================================================

class BaseRule:
    """
    Abstract base for detection rules.

    Subclasses set ``name`` (a rule ID like ``"log.failed_login_burst"``)
    and implement ``evaluate()``.
    """
    name: str = ""

    def evaluate(self, context: AgentContext) -> FindingSpec | None:
        raise NotImplementedError


# ============================================================================
# RULE 1 — Failed Login Burst
# ============================================================================

class FailedLoginBurstRule(BaseRule):
    """
    Detects N failed logins from the same user and IP within a short
    window. The classic brute-force / credential-stuffing signal.

    Triggers on ``failed_login`` events (or ``login`` events with
    ``outcome="failure"``). The finding merges with itself across
    successive fires (occurrence_count increments), so an attacker
    who keeps trying sees one finding that grows.

    MITRE: T1110.001 (Brute Force: Password Guessing)
    """
    name = "log.failed_login_burst"

    def __init__(self, threshold: int = 5, window_minutes: int = 10) -> None:
        self._threshold = max(2, threshold)
        self._window_minutes = max(1, window_minutes)

    def evaluate(self, context: AgentContext) -> FindingSpec | None:
        event = context.event

        # Applicability check — must be a failed auth event
        is_failed_auth = (
            event.event_type == "failed_login"
            or (
                event.event_type in ("login", "authentication")
                and (event.outcome or "").lower() in ("failure", "failed")
            )
        )
        if not is_failed_auth:
            return None

        # No identifier → can't aggregate
        if not event.username and not event.source_ip:
            return None

        # Aggregate failed logins in the window
        cutoff = event.event_time - timedelta(minutes=self._window_minutes)
        stmt = (
            select(SecurityEvent)
            .where(
                SecurityEvent.workspace_id == context.workspace_id,
                SecurityEvent.event_time >= cutoff,
                SecurityEvent.event_time <= event.event_time,
            )
            .limit(self._threshold * 4)   # bounded scan
        )
        # Filter by the same user AND/OR ip — whichever is present
        if event.username:
            stmt = stmt.where(SecurityEvent.username == event.username)
        if event.source_ip:
            stmt = stmt.where(SecurityEvent.source_ip == event.source_ip)
        # Same failed-auth criterion on the aggregate
        stmt = stmt.where(
            (SecurityEvent.event_type == "failed_login")
            | (
                SecurityEvent.event_type.in_(("login", "authentication"))
                & SecurityEvent.outcome.in_(("failure", "failed", "FAILURE", "FAILED"))
            )
        )

        matching = list(context.db.execute(stmt).scalars().all())

        if len(matching) < self._threshold:
            return None

        # Confidence scales from 0.70 (exactly at threshold) up toward 0.99
        confidence = min(0.99, 0.70 + 0.05 * (len(matching) - self._threshold))

        # Dedup hint — same user + IP = same finding
        dedup_parts = []
        if event.username:
            dedup_parts.append(f"user={event.username}")
        if event.source_ip:
            dedup_parts.append(f"ip={event.source_ip}")
        dedup_hint = "|".join(dedup_parts) if dedup_parts else "unknown"

        desc_parts = [f"{len(matching)} failed login attempts"]
        if event.username:
            desc_parts.append(f"targeting {event.username}")
        if event.source_ip:
            desc_parts.append(f"from {event.source_ip}")
        desc_parts.append(f"within {self._window_minutes} minutes")

        return FindingSpec(
            rule_id=self.name,
            title=f"Repeated failed logins ({len(matching)} attempts)",
            severity=EventSeverity.HIGH,
            category=FindingCategory.BRUTE_FORCE,
            confidence=confidence,
            event_ids=[e.id for e in matching],
            primary_event_id=event.id,
            evidence={
                "threshold": self._threshold,
                "window_minutes": self._window_minutes,
                "matched_count": len(matching),
                "username": event.username,
                "source_ip": event.source_ip,
                "hostnames": sorted({e.hostname for e in matching if e.hostname})[:10],
            },
            description=" ".join(desc_parts) + ".",
            mitre_techniques=["T1110.001"],
            dedup_hint=dedup_hint,
        )


# ============================================================================
# RULE 2 — Privilege Escalation
# ============================================================================

_PRIVILEGE_EVENT_TYPES = frozenset({
    "privilege_escalation",
    "sudo",
    "sudo_failure",
    "role_change",
    "user_added_to_group",
    "group_modified",
    "setuid_exec",
    "capability_change",
    "elevated_command",
})


class PrivilegeEscalationRule(BaseRule):
    """
    Detects privilege-change events: sudo, setuid, role changes,
    group membership additions.

    Fires on any event whose ``event_type`` is in the privilege-change
    vocabulary. Confidence is higher for failures (attacker attempted
    and was denied) than for successes (could be legitimate).

    MITRE: T1068 (Exploitation for Privilege Escalation),
           T1548 (Abuse Elevation Control Mechanism)
    """
    name = "log.privilege_escalation"

    def __init__(self, enabled: bool = True) -> None:
        self._enabled = enabled

    def evaluate(self, context: AgentContext) -> FindingSpec | None:
        if not self._enabled:
            return None

        event = context.event
        if event.event_type not in _PRIVILEGE_EVENT_TYPES:
            return None

        outcome = (event.outcome or "").lower()
        confidence = 0.85 if outcome in ("failure", "failed", "denied") else 0.70

        return FindingSpec(
            rule_id=self.name,
            title=f"Privilege change: {event.event_type}",
            severity=EventSeverity.HIGH,
            category=FindingCategory.PRIVILEGE_ESCALATION,
            confidence=confidence,
            event_ids=[event.id],
            evidence={
                "event_type": event.event_type,
                "outcome": event.outcome,
                "username": event.username,
                "hostname": event.hostname,
                "process_name": event.process_name,
            },
            description=(
                f"Privilege-changing event '{event.event_type}' "
                + (f"by {event.username} " if event.username else "")
                + (f"on {event.hostname}" if event.hostname else "")
            ).strip(),
            mitre_techniques=["T1068", "T1548"],
            dedup_hint=f"host={event.hostname or 'unknown'}|user={event.username or 'unknown'}",
        )


# ============================================================================
# RULE 3 — Account Modification
# ============================================================================

_ACCOUNT_EVENT_TYPES = frozenset({
    "user_created",
    "user_deleted",
    "user_modified",
    "password_changed",
    "account_locked",
    "account_unlocked",
    "account_disabled",
    "account_enabled",
})


class AccountModificationRule(BaseRule):
    """
    Detects account lifecycle changes: new users, deletions, password
    changes, lockouts.

    Severity is HIGH for account creation/deletion (attacker persistence
    or sabotage) and MEDIUM for other changes (often legitimate admin
    activity).

    MITRE: T1136 (Create Account), T1098 (Account Manipulation)
    """
    name = "log.account_modification"

    def evaluate(self, context: AgentContext) -> FindingSpec | None:
        event = context.event
        if event.event_type not in _ACCOUNT_EVENT_TYPES:
            return None

        # Creation/deletion are more significant
        if event.event_type in ("user_created", "user_deleted"):
            severity = EventSeverity.HIGH
            confidence = 0.75
        else:
            severity = EventSeverity.MEDIUM
            confidence = 0.65

        return FindingSpec(
            rule_id=self.name,
            title=f"Account modification: {event.event_type.replace('_', ' ')}",
            severity=severity,
            category=FindingCategory.POLICY_VIOLATION,
            confidence=confidence,
            event_ids=[event.id],
            evidence={
                "event_type": event.event_type,
                "target_username": event.username,
                "hostname": event.hostname,
                "outcome": event.outcome,
            },
            description=(
                f"Account event '{event.event_type}' "
                + (f"for {event.username} " if event.username else "")
                + (f"on {event.hostname}" if event.hostname else "")
            ).strip(),
            mitre_techniques=["T1136", "T1098"],
            dedup_hint=f"type={event.event_type}|user={event.username or 'unknown'}",
        )


# ============================================================================
# RULE 4 — Suspicious File Access
# ============================================================================

_SENSITIVE_PATH_PATTERNS = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/.ssh/id_rsa",
    "/.ssh/id_ed25519",
    "/.ssh/authorized_keys",
    "/.aws/credentials",
    "/.kube/config",
    "\\windows\\system32\\config\\sam",
    "\\windows\\system32\\config\\system",
    "\\windows\\system32\\config\\security",
    "\\users\\administrator\\.ssh",
)


class SuspiciousFileAccessRule(BaseRule):
    """
    Detects access to known-sensitive files: passwd, shadow, SSH keys,
    cloud credentials, SAM/SYSTEM registry hives.

    These files are the primary target of credential-theft tooling.
    Access to them by a non-admin process is often the first signal
    of a compromise.

    MITRE: T1005 (Data from Local System),
           T1083 (File and Directory Discovery)
    """
    name = "log.suspicious_file_access"

    def evaluate(self, context: AgentContext) -> FindingSpec | None:
        event = context.event
        if not event.file_path:
            return None

        path_lower = event.file_path.lower().replace("/", "\\") if "\\" in event.file_path else event.file_path.lower()

        matched = None
        for pattern in _SENSITIVE_PATH_PATTERNS:
            normalized_pattern = pattern.replace("/", "\\") if "\\" in event.file_path else pattern
            if normalized_pattern in path_lower:
                matched = pattern
                break

        if matched is None:
            return None

        return FindingSpec(
            rule_id=self.name,
            title=f"Sensitive file access: {event.file_path}",
            severity=EventSeverity.MEDIUM,
            category=FindingCategory.OTHER,
            confidence=0.75,
            event_ids=[event.id],
            evidence={
                "file_path": event.file_path,
                "matched_pattern": matched,
                "username": event.username,
                "hostname": event.hostname,
                "process_name": event.process_name,
            },
            description=(
                f"Access to sensitive path '{event.file_path}' matched "
                f"known credential/configuration target '{matched}'."
            ),
            mitre_techniques=["T1005", "T1083"],
            dedup_hint=f"host={event.hostname or 'unknown'}|path={event.file_path}",
        )


# ============================================================================
# RULE 5 — Unusual Login
# ============================================================================

class UnusualLoginRule(BaseRule):
    """
    Detects successful logins from a source IP that the user hasn't
    used in the last N days.

    Requires a **30-day baseline** to be accurate. For a brand-new
    user (no history), it fires with lower confidence — the analyst
    reviews whether the login is legitimate.

    MITRE: T1078 (Valid Accounts)
    """
    name = "log.unusual_login"

    _HISTORY_DAYS = 30

    def evaluate(self, context: AgentContext) -> FindingSpec | None:
        event = context.event

        # Only successful authentication events with a user + IP
        if event.category != EventCategory.AUTHENTICATION:
            return None
        outcome = (event.outcome or "").lower()
        if outcome and outcome not in ("success", "succeeded", "authenticated"):
            return None
        if not event.username or not event.source_ip:
            return None

        # Get known IPs used by this user in the last 30 days (excluding
        # the current one, which we're about to test)
        cutoff = event.event_time - timedelta(days=self._HISTORY_DAYS)
        stmt = (
            select(func.distinct(SecurityEvent.source_ip))
            .where(
                SecurityEvent.workspace_id == context.workspace_id,
                SecurityEvent.category == EventCategory.AUTHENTICATION,
                SecurityEvent.username == event.username,
                SecurityEvent.source_ip.is_not(None),
                SecurityEvent.event_time >= cutoff,
                SecurityEvent.event_time < event.event_time,
            )
        )
        known_ips: set[str] = {
            ip for (ip,) in context.db.execute(stmt).all() if ip
        }

        if event.source_ip in known_ips:
            return None  # not unusual — user has logged in from here

        # New IP for this user
        confidence = 0.70 if known_ips else 0.55  # lower confidence if no baseline

        return FindingSpec(
            rule_id=self.name,
            title=f"New login location for {event.username}",
            severity=EventSeverity.MEDIUM,
            category=FindingCategory.SUSPICIOUS_LOGIN,
            confidence=confidence,
            event_ids=[event.id],
            evidence={
                "username": event.username,
                "source_ip": event.source_ip,
                "hostname": event.hostname,
                "history_days": self._HISTORY_DAYS,
                "known_ip_count": len(known_ips),
            },
            description=(
                f"Successful login for {event.username} from "
                f"{event.source_ip}, which has not been used by this user "
                f"in the last {self._HISTORY_DAYS} days "
                f"({len(known_ips)} prior IPs on record)."
            ),
            mitre_techniques=["T1078"],
            dedup_hint=f"user={event.username}|ip={event.source_ip}",
        )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "FindingSpec",
    "BaseRule",
    "FailedLoginBurstRule",
    "PrivilegeEscalationRule",
    "AccountModificationRule",
    "SuspiciousFileAccessRule",
    "UnusualLoginRule",
]