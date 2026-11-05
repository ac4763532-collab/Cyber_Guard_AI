"""
CyberGuard AI - Windows Event Log Detection Rules

STEP 8.2: Deterministic detection rules for Windows Event Log events.

Rules:
- WIN-001: Failed Authentication Burst (4625)
- WIN-002: Authentication Sequence (4625 → 4624)
- WIN-003: Privileged Activity (4672)

Design principles:
- Conservative and explainable
- Configurable thresholds
- Uses existing Finding model
- Integrates with existing RuleRegistry
- No invented "malicious" labels without evidence
"""

from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any
from uuid import uuid4

import structlog

from app.detection.rules.base import (
    DetectionRule,
    RuleMatch,
    RuleSeverity,
    RuleCategory,
)


logger = structlog.get_logger(__name__)


# =============================================================================
# Configuration (can be overridden via Settings)
# =============================================================================

# Default thresholds - these should be configurable
DEFAULT_FAILED_AUTH_THRESHOLD = 5
DEFAULT_FAILED_AUTH_WINDOW_SECONDS = 300  # 5 minutes
DEFAULT_SEQUENCE_FAILURE_THRESHOLD = 3  # Failures before success to flag


# =============================================================================
# WIN-001: Failed Authentication Burst Rule
# =============================================================================


class WindowsFailedAuthBurstRule(DetectionRule):
    """
    Detects repeated failed authentication attempts (Event ID 4625).

    This rule does NOT automatically declare an "attack" - it creates
    a finding indicating repeated failures that warrant investigation.

    Correlates by:
    - Username
    - Source IP (when available)
    - Time window

    Configurable:
    - Failure threshold (default: 5)
    - Time window (default: 5 minutes)
    """

    def __init__(
        self,
        threshold: int = DEFAULT_FAILED_AUTH_THRESHOLD,
        window_seconds: int = DEFAULT_FAILED_AUTH_WINDOW_SECONDS,
        enabled: bool = True,
    ):
        super().__init__(
            rule_id="WIN-001",
            rule_name="Windows Failed Authentication Burst",
            description=(
                "Detects repeated Windows authentication failures (4625) "
                "within a configurable time window"
            ),
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.BRUTE_FORCE,
            enabled=enabled,
            confidence=0.8,
            mitre_techniques=["T1110.001", "T1110.003"],
        )
        self.threshold = threshold
        self.window_seconds = window_seconds

        # In-memory tracking for correlation within detection window
        # Key: (username, source_ip) -> list of event timestamps
        self._failure_tracker: dict[tuple[str, str | None], list[dict]] = defaultdict(list)

    def evaluate(self, data: dict[str, Any]) -> RuleMatch | None:
        """
        Evaluate a Windows event for failed auth burst pattern.

        Expected data structure:
        {
            "event_code": "4625",
            "target_user": "username",
            "source_ip": "1.2.3.4" or None,
            "timestamp": datetime or ISO string,
            "hostname": "COMPUTER",
            "source_event_id": "win-xxx-12345",
            ...
        }
        """
        if not self.enabled:
            return None

        # Only process 4625 events
        event_code = str(data.get("event_code", ""))
        if event_code != "4625":
            return None

        username = data.get("target_user") or data.get("username") or "unknown"
        source_ip = data.get("source_ip")
        hostname = data.get("hostname") or data.get("computer_name") or "unknown"

        # Parse timestamp
        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.now(timezone.utc)
        elif not isinstance(timestamp, datetime):
            timestamp = datetime.now(timezone.utc)

        # Track this failure
        key = (username.lower(), source_ip)
        event_record = {
            "timestamp": timestamp,
            "hostname": hostname,
            "source_event_id": data.get("source_event_id"),
            "source_ip": source_ip,
            "logon_type": data.get("logon_type"),
            "status": data.get("status"),
            "failure_reason": data.get("failure_reason"),
        }
        self._failure_tracker[key].append(event_record)

        # Clean old entries outside window
        cutoff = timestamp - timedelta(seconds=self.window_seconds)
        self._failure_tracker[key] = [
            e for e in self._failure_tracker[key]
            if e["timestamp"] >= cutoff
        ]

        # Check if threshold reached
        failures = self._failure_tracker[key]
        if len(failures) < self.threshold:
            return None

        # Threshold reached - create finding
        first_failure = min(failures, key=lambda e: e["timestamp"])
        last_failure = max(failures, key=lambda e: e["timestamp"])

        # Collect unique hostnames
        hostnames = list(set(e["hostname"] for e in failures))

        # Build evidence
        evidence = [
            f"Username: {username}",
            f"Failure count: {len(failures)}",
            f"Time window: {self.window_seconds} seconds",
            f"First failure: {first_failure['timestamp'].isoformat()}",
            f"Last failure: {last_failure['timestamp'].isoformat()}",
            f"Host(s): {', '.join(hostnames)}",
        ]
        if source_ip:
            evidence.append(f"Source IP: {source_ip}")

        # Collect source event IDs
        event_ids = [e["source_event_id"] for e in failures if e.get("source_event_id")]

        return self._create_match(
            description=(
                f"Repeated authentication failures for user '{username}': "
                f"{len(failures)} failures in {self.window_seconds}s"
            ),
            evidence=evidence,
            matched_data={
                "username": username,
                "source_ip": source_ip,
                "failure_count": len(failures),
                "threshold": self.threshold,
                "window_seconds": self.window_seconds,
                "first_observed": first_failure["timestamp"].isoformat(),
                "last_observed": last_failure["timestamp"].isoformat(),
                "hostnames": hostnames,
                "source_event_ids": event_ids,
                "event_code": "4625",
            },
        )

    def reset_tracker(self) -> None:
        """Clear the failure tracker (for testing or memory management)."""
        self._failure_tracker.clear()


# =============================================================================
# WIN-002: Authentication Sequence Rule (4625 → 4624)
# =============================================================================


class WindowsAuthSequenceRule(DetectionRule):
    """
    Detects successful authentication following repeated failures.

    Pattern: Multiple 4625 (failed) followed by 4624 (success)
    for the same username/source.

    This does NOT claim the sequence is malicious. It creates a finding
    indicating the sequence warrants investigation.

    Configurable:
    - Minimum failures before success to flag (default: 3)
    - Time window (default: 5 minutes)
    """

    def __init__(
        self,
        failure_threshold: int = DEFAULT_SEQUENCE_FAILURE_THRESHOLD,
        window_seconds: int = DEFAULT_FAILED_AUTH_WINDOW_SECONDS,
        enabled: bool = True,
    ):
        super().__init__(
            rule_id="WIN-002",
            rule_name="Windows Authentication Sequence",
            description=(
                "Detects successful login (4624) following repeated failures (4625)"
            ),
            severity=RuleSeverity.HIGH,
            category=RuleCategory.CREDENTIAL_ACCESS,
            enabled=enabled,
            confidence=0.75,
            mitre_techniques=["T1110", "T1078"],
        )
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds

        # Track recent failures per (username, source_ip)
        self._failure_history: dict[tuple[str, str | None], list[dict]] = defaultdict(list)

    def evaluate(self, data: dict[str, Any]) -> RuleMatch | None:
        """
        Evaluate for authentication sequence pattern.

        Tracks 4625 events and triggers on 4624 if preceded by failures.
        """
        if not self.enabled:
            return None

        event_code = str(data.get("event_code", ""))
        if event_code not in ("4624", "4625"):
            return None

        username = data.get("target_user") or data.get("username") or "unknown"
        source_ip = data.get("source_ip")
        hostname = data.get("hostname") or "unknown"

        # Parse timestamp
        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.now(timezone.utc)
        elif not isinstance(timestamp, datetime):
            timestamp = datetime.now(timezone.utc)

        key = (username.lower(), source_ip)

        if event_code == "4625":
            # Track failure
            self._failure_history[key].append({
                "timestamp": timestamp,
                "hostname": hostname,
                "source_event_id": data.get("source_event_id"),
                "logon_type": data.get("logon_type"),
            })

            # Clean old entries
            cutoff = timestamp - timedelta(seconds=self.window_seconds)
            self._failure_history[key] = [
                e for e in self._failure_history[key]
                if e["timestamp"] >= cutoff
            ]
            return None

        # event_code == "4624" - Check for preceding failures
        failures = self._failure_history.get(key, [])

        # Clean old entries
        cutoff = timestamp - timedelta(seconds=self.window_seconds)
        failures = [e for e in failures if e["timestamp"] >= cutoff]
        self._failure_history[key] = failures

        if len(failures) < self.failure_threshold:
            # Clear failures after successful login
            self._failure_history[key] = []
            return None

        # Sequence detected
        first_failure = min(failures, key=lambda e: e["timestamp"])
        failure_event_ids = [e["source_event_id"] for e in failures if e.get("source_event_id")]

        evidence = [
            f"Username: {username}",
            f"Failed attempts before success: {len(failures)}",
            f"Successful login host: {hostname}",
            f"Successful login time: {timestamp.isoformat()}",
            f"First failure: {first_failure['timestamp'].isoformat()}",
            f"Logon type: {data.get('logon_type', 'unknown')}",
        ]
        if source_ip:
            evidence.append(f"Source IP: {source_ip}")

        # Clear failures after detection
        self._failure_history[key] = []

        return self._create_match(
            description=(
                f"Successful authentication for '{username}' after "
                f"{len(failures)} failed attempts"
            ),
            evidence=evidence,
            matched_data={
                "username": username,
                "source_ip": source_ip,
                "failure_count": len(failures),
                "success_event_id": data.get("source_event_id"),
                "failure_event_ids": failure_event_ids,
                "success_timestamp": timestamp.isoformat(),
                "first_failure_timestamp": first_failure["timestamp"].isoformat(),
                "hostname": hostname,
                "logon_type": data.get("logon_type"),
                "event_codes": ["4625", "4624"],
            },
        )

    def reset_tracker(self) -> None:
        """Clear the failure history (for testing)."""
        self._failure_history.clear()


# =============================================================================
# WIN-003: Privileged Activity Rule (4672)
# =============================================================================


class WindowsPrivilegedActivityRule(DetectionRule):
    """
    Creates a finding for privileged logon activity (Event ID 4672).

    This is an observability signal, NOT proof of malicious behavior.
    Every 4672 is NOT labeled as an attack.

    The finding provides visibility into privileged activity for
    security monitoring and audit trails.
    """

    def __init__(self, enabled: bool = True):
        super().__init__(
            rule_id="WIN-003",
            rule_name="Windows Privileged Activity",
            description="Observes special privileges assigned to logon session (4672)",
            severity=RuleSeverity.LOW,  # Observability, not threat
            category=RuleCategory.PRIVILEGE_ESCALATION,
            enabled=enabled,
            confidence=1.0,  # This is factual observation
            mitre_techniques=["T1078.002"],  # Valid Accounts: Domain Accounts
        )

    def evaluate(self, data: dict[str, Any]) -> RuleMatch | None:
        """
        Create an observability finding for 4672 events.

        Every 4672 creates a low-severity finding for audit purposes.
        """
        if not self.enabled:
            return None

        event_code = str(data.get("event_code", ""))
        if event_code != "4672":
            return None

        username = data.get("subject_user") or data.get("username") or "unknown"
        domain = data.get("subject_domain") or data.get("domain") or ""
        hostname = data.get("hostname") or data.get("computer_name") or "unknown"
        privileges = data.get("privileges") or data.get("privilege_list") or "unknown"

        # Parse timestamp
        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.now(timezone.utc)
        elif not isinstance(timestamp, datetime):
            timestamp = datetime.now(timezone.utc)

        # Format user with domain
        full_user = f"{domain}\\{username}" if domain else username

        evidence = [
            f"Account: {full_user}",
            f"Host: {hostname}",
            f"Timestamp: {timestamp.isoformat()}",
            f"Privileges: {privileges}",
        ]

        if data.get("source_event_id"):
            evidence.append(f"Event ID: {data['source_event_id']}")

        return self._create_match(
            description=f"Privileged logon session for '{full_user}' on {hostname}",
            evidence=evidence,
            matched_data={
                "username": username,
                "domain": domain,
                "full_user": full_user,
                "hostname": hostname,
                "privileges": privileges,
                "timestamp": timestamp.isoformat(),
                "source_event_id": data.get("source_event_id"),
                "event_code": "4672",
            },
            confidence_override=1.0,  # This is factual, not probabilistic
        )


# =============================================================================
# Rule Registration
# =============================================================================


def register_windows_rules(
    registry,
    failed_auth_threshold: int = DEFAULT_FAILED_AUTH_THRESHOLD,
    failed_auth_window: int = DEFAULT_FAILED_AUTH_WINDOW_SECONDS,
    sequence_threshold: int = DEFAULT_SEQUENCE_FAILURE_THRESHOLD,
    enable_privileged_rule: bool = True,
) -> list[str]:
    """
    Register Windows detection rules with the rule registry.

    Args:
        registry: RuleRegistry instance
        failed_auth_threshold: Failures to trigger burst detection
        failed_auth_window: Window in seconds for burst detection
        sequence_threshold: Failures before success to flag sequence
        enable_privileged_rule: Whether to enable 4672 detection

    Returns:
        List of registered rule IDs
    """
    rules = [
        WindowsFailedAuthBurstRule(
            threshold=failed_auth_threshold,
            window_seconds=failed_auth_window,
        ),
        WindowsAuthSequenceRule(
            failure_threshold=sequence_threshold,
            window_seconds=failed_auth_window,
        ),
        WindowsPrivilegedActivityRule(
            enabled=enable_privileged_rule,
        ),
    ]

    registered = []
    for rule in rules:
        registry.register(rule)
        registered.append(rule.rule_id)
        logger.info(
            "Registered Windows rule",
            rule_id=rule.rule_id,
            rule_name=rule.rule_name,
        )

    return registered


# =============================================================================
# Standalone rule instances for direct use
# =============================================================================

_failed_auth_rule: WindowsFailedAuthBurstRule | None = None
_auth_sequence_rule: WindowsAuthSequenceRule | None = None
_privileged_rule: WindowsPrivilegedActivityRule | None = None


def get_windows_failed_auth_rule(
    threshold: int = DEFAULT_FAILED_AUTH_THRESHOLD,
    window_seconds: int = DEFAULT_FAILED_AUTH_WINDOW_SECONDS,
) -> WindowsFailedAuthBurstRule:
    """Get or create the failed auth burst rule."""
    global _failed_auth_rule
    if _failed_auth_rule is None:
        _failed_auth_rule = WindowsFailedAuthBurstRule(
            threshold=threshold,
            window_seconds=window_seconds,
        )
    return _failed_auth_rule


def get_windows_auth_sequence_rule(
    failure_threshold: int = DEFAULT_SEQUENCE_FAILURE_THRESHOLD,
    window_seconds: int = DEFAULT_FAILED_AUTH_WINDOW_SECONDS,
) -> WindowsAuthSequenceRule:
    """Get or create the auth sequence rule."""
    global _auth_sequence_rule
    if _auth_sequence_rule is None:
        _auth_sequence_rule = WindowsAuthSequenceRule(
            failure_threshold=failure_threshold,
            window_seconds=window_seconds,
        )
    return _auth_sequence_rule


def get_windows_privileged_rule() -> WindowsPrivilegedActivityRule:
    """Get or create the privileged activity rule."""
    global _privileged_rule
    if _privileged_rule is None:
        _privileged_rule = WindowsPrivilegedActivityRule()
    return _privileged_rule
