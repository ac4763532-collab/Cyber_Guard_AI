"""
CyberGuard AI - Redis-Backed Windows Detection Rules

STEP 8.2.1: Production-ready Windows detection rules using Redis state.

These rules replace the in-memory versions for production use:
- State survives worker restarts
- Multi-worker safe with atomic operations
- Tenant isolated
- Automatic TTL cleanup

Usage:
    state_manager = await get_detection_state_manager(tenant_id)
    rule = RedisWindowsFailedAuthBurstRule(state_manager, threshold=5)
    match = await rule.evaluate_async(event_data)
"""

from datetime import datetime, timezone, timedelta
from typing import Any

import structlog

from app.detection.rules.base import (
    DetectionRule,
    RuleMatch,
    RuleSeverity,
    RuleCategory,
)
from app.detection.state.redis_state import (
    DetectionStateManager,
    RedisUnavailableError,
)


logger = structlog.get_logger(__name__)


# =============================================================================
# WIN-001: Redis-Backed Failed Authentication Burst Rule
# =============================================================================


class RedisWindowsFailedAuthBurstRule(DetectionRule):
    """
    Redis-backed detection of repeated failed authentication attempts.

    Uses Redis sorted sets for windowed event tracking, enabling:
    - Multi-worker concurrent processing
    - State persistence across restarts
    - Automatic TTL-based cleanup
    - Tenant isolation
    """

    def __init__(
        self,
        state_manager: DetectionStateManager,
        threshold: int = 5,
        window_seconds: int = 300,
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
        self._state = state_manager
        self.threshold = threshold
        self.window_seconds = window_seconds

    def evaluate(self, data: dict[str, Any]) -> RuleMatch | None:
        """
        Synchronous evaluate not supported for Redis-backed rules.

        Use evaluate_async instead.
        """
        raise NotImplementedError(
            "Redis-backed rules require async evaluation. Use evaluate_async()."
        )

    async def evaluate_async(self, data: dict[str, Any]) -> RuleMatch | None:
        """
        Evaluate a Windows event for failed auth burst pattern.

        Args:
            data: Event data with event_code, target_user, source_ip, etc.

        Returns:
            RuleMatch if threshold reached, None otherwise

        Raises:
            RedisUnavailableError: If Redis is not available
        """
        if not self.enabled:
            return None

        # Only process 4625 events
        event_code = str(data.get("event_code", ""))
        if event_code != "4625":
            return None

        # Check idempotency
        source_event_id = data.get("source_event_id")
        if source_event_id:
            is_new = await self._state.check_and_mark_processed(
                self.rule_id,
                source_event_id,
                ttl_seconds=self.window_seconds + 60,
            )
            if not is_new:
                logger.debug(
                    "Skipping duplicate event",
                    rule_id=self.rule_id,
                    source_event_id=source_event_id,
                )
                return None

        username = data.get("target_user") or data.get("username") or "unknown"
        source_ip = data.get("source_ip")
        hostname = data.get("hostname") or data.get("computer_name") or "unknown"

        # Parse timestamp
        timestamp = self._parse_timestamp(data.get("timestamp"))

        # Build correlation key
        correlation_key = f"{username.lower()}@{source_ip or 'unknown'}"

        # Build event record to store
        event_record = {
            "timestamp": timestamp.isoformat(),
            "hostname": hostname,
            "source_event_id": source_event_id,
            "source_ip": source_ip,
            "logon_type": data.get("logon_type"),
            "status": data.get("status"),
            "failure_reason": data.get("failure_reason"),
        }

        # Add event to Redis and check threshold atomically
        await self._state.add_event(
            rule_id=self.rule_id,
            correlation_key=correlation_key,
            event_data=event_record,
            timestamp=timestamp,
            window_seconds=self.window_seconds,
        )

        # Check if threshold reached
        threshold_reached, events = await self._state.check_threshold_and_get_events(
            rule_id=self.rule_id,
            correlation_key=correlation_key,
            threshold=self.threshold,
            window_seconds=self.window_seconds,
        )

        if not threshold_reached:
            return None

        # Threshold reached - create finding
        # Parse timestamps from stored events
        event_timestamps = []
        for e in events:
            try:
                ts = datetime.fromisoformat(e.get("timestamp", ""))
                event_timestamps.append(ts)
            except (ValueError, TypeError):
                pass

        if not event_timestamps:
            event_timestamps = [timestamp]

        first_failure = min(event_timestamps)
        last_failure = max(event_timestamps)

        # Collect unique hostnames
        hostnames = list(set(e.get("hostname", "unknown") for e in events))

        # Collect source event IDs
        event_ids = [e.get("source_event_id") for e in events if e.get("source_event_id")]

        # Compute finding fingerprint for deduplication
        fingerprint = self._state.compute_finding_fingerprint(
            rule_id=self.rule_id,
            correlation_key=correlation_key,
            window_start=first_failure,
            window_end=last_failure,
        )

        # Check if we already created a finding for this
        is_new_finding = await self._state.mark_finding_created(
            fingerprint=fingerprint,
            finding_id=fingerprint,  # Will be replaced with actual finding ID
            ttl_seconds=self.window_seconds,
        )

        if not is_new_finding:
            logger.debug(
                "Skipping duplicate finding",
                rule_id=self.rule_id,
                fingerprint=fingerprint,
            )
            return None

        # Build evidence
        evidence = [
            f"Username: {username}",
            f"Failure count: {len(events)}",
            f"Time window: {self.window_seconds} seconds",
            f"First failure: {first_failure.isoformat()}",
            f"Last failure: {last_failure.isoformat()}",
            f"Host(s): {', '.join(hostnames)}",
        ]
        if source_ip:
            evidence.append(f"Source IP: {source_ip}")

        return self._create_match(
            description=(
                f"Repeated authentication failures for user '{username}': "
                f"{len(events)} failures in {self.window_seconds}s"
            ),
            evidence=evidence,
            matched_data={
                "username": username,
                "source_ip": source_ip,
                "failure_count": len(events),
                "threshold": self.threshold,
                "window_seconds": self.window_seconds,
                "first_observed": first_failure.isoformat(),
                "last_observed": last_failure.isoformat(),
                "hostnames": hostnames,
                "source_event_ids": event_ids,
                "event_code": "4625",
                "fingerprint": fingerprint,
            },
        )

    def _parse_timestamp(self, timestamp: Any) -> datetime:
        """Parse timestamp from various formats."""
        if isinstance(timestamp, str):
            try:
                return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                return datetime.now(timezone.utc)
        elif isinstance(timestamp, datetime):
            return timestamp
        else:
            return datetime.now(timezone.utc)


# =============================================================================
# WIN-002: Redis-Backed Authentication Sequence Rule
# =============================================================================


class RedisWindowsAuthSequenceRule(DetectionRule):
    """
    Redis-backed detection of successful login following failures.

    Pattern: Multiple 4625 (failed) followed by 4624 (success)

    Uses Redis sorted sets for tracking failure history across workers.
    """

    def __init__(
        self,
        state_manager: DetectionStateManager,
        failure_threshold: int = 3,
        window_seconds: int = 300,
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
        self._state = state_manager
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds

    def evaluate(self, data: dict[str, Any]) -> RuleMatch | None:
        """Use evaluate_async for Redis-backed rules."""
        raise NotImplementedError(
            "Redis-backed rules require async evaluation. Use evaluate_async()."
        )

    async def evaluate_async(self, data: dict[str, Any]) -> RuleMatch | None:
        """
        Evaluate for authentication sequence pattern.

        Tracks 4625 events and triggers on 4624 if preceded by failures.
        """
        if not self.enabled:
            return None

        event_code = str(data.get("event_code", ""))
        if event_code not in ("4624", "4625"):
            return None

        # Check idempotency
        source_event_id = data.get("source_event_id")
        if source_event_id:
            is_new = await self._state.check_and_mark_processed(
                self.rule_id,
                source_event_id,
                ttl_seconds=self.window_seconds + 60,
            )
            if not is_new:
                return None

        username = data.get("target_user") or data.get("username") or "unknown"
        source_ip = data.get("source_ip")
        hostname = data.get("hostname") or "unknown"

        timestamp = self._parse_timestamp(data.get("timestamp"))

        # Use separate key prefix for failure tracking
        correlation_key = f"seq:{username.lower()}@{source_ip or 'unknown'}"

        if event_code == "4625":
            # Track failure
            event_record = {
                "timestamp": timestamp.isoformat(),
                "hostname": hostname,
                "source_event_id": source_event_id,
                "logon_type": data.get("logon_type"),
            }

            await self._state.add_event(
                rule_id=self.rule_id,
                correlation_key=correlation_key,
                event_data=event_record,
                timestamp=timestamp,
                window_seconds=self.window_seconds,
            )
            return None

        # event_code == "4624" - Check for preceding failures
        threshold_reached, failures = await self._state.check_threshold_and_get_events(
            rule_id=self.rule_id,
            correlation_key=correlation_key,
            threshold=self.failure_threshold,
            window_seconds=self.window_seconds,
        )

        # Clear failures after success (regardless of threshold)
        await self._state.clear_events(self.rule_id, correlation_key)

        if not threshold_reached:
            return None

        # Sequence detected - parse failure timestamps
        failure_timestamps = []
        for f in failures:
            try:
                ts = datetime.fromisoformat(f.get("timestamp", ""))
                failure_timestamps.append(ts)
            except (ValueError, TypeError):
                pass

        if not failure_timestamps:
            failure_timestamps = [timestamp - timedelta(seconds=60)]

        first_failure = min(failure_timestamps)
        failure_event_ids = [f.get("source_event_id") for f in failures if f.get("source_event_id")]

        # Compute fingerprint for deduplication
        fingerprint = self._state.compute_finding_fingerprint(
            rule_id=self.rule_id,
            correlation_key=correlation_key,
            window_start=first_failure,
            window_end=timestamp,
        )

        is_new_finding = await self._state.mark_finding_created(
            fingerprint=fingerprint,
            finding_id=fingerprint,
            ttl_seconds=self.window_seconds,
        )

        if not is_new_finding:
            return None

        evidence = [
            f"Username: {username}",
            f"Failed attempts before success: {len(failures)}",
            f"Successful login host: {hostname}",
            f"Successful login time: {timestamp.isoformat()}",
            f"First failure: {first_failure.isoformat()}",
            f"Logon type: {data.get('logon_type', 'unknown')}",
        ]
        if source_ip:
            evidence.append(f"Source IP: {source_ip}")

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
                "success_event_id": source_event_id,
                "failure_event_ids": failure_event_ids,
                "success_timestamp": timestamp.isoformat(),
                "first_failure_timestamp": first_failure.isoformat(),
                "hostname": hostname,
                "logon_type": data.get("logon_type"),
                "event_codes": ["4625", "4624"],
                "fingerprint": fingerprint,
            },
        )

    def _parse_timestamp(self, timestamp: Any) -> datetime:
        """Parse timestamp from various formats."""
        if isinstance(timestamp, str):
            try:
                return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                return datetime.now(timezone.utc)
        elif isinstance(timestamp, datetime):
            return timestamp
        else:
            return datetime.now(timezone.utc)


# =============================================================================
# Factory for Redis-Backed Rules
# =============================================================================


async def create_redis_windows_rules(
    state_manager: DetectionStateManager,
    failed_auth_threshold: int = 5,
    failed_auth_window: int = 300,
    sequence_threshold: int = 3,
    enable_privileged_rule: bool = True,
) -> dict[str, DetectionRule]:
    """
    Create Redis-backed Windows detection rules.

    Args:
        state_manager: DetectionStateManager for Redis operations
        failed_auth_threshold: Threshold for WIN-001
        failed_auth_window: Window in seconds
        sequence_threshold: Threshold for WIN-002
        enable_privileged_rule: Whether to include WIN-003 (stateless)

    Returns:
        Dict of rule_id -> rule instance
    """
    # Import here to avoid circular imports
    from app.detection.rules.windows import WindowsPrivilegedActivityRule

    rules = {
        "WIN-001": RedisWindowsFailedAuthBurstRule(
            state_manager=state_manager,
            threshold=failed_auth_threshold,
            window_seconds=failed_auth_window,
        ),
        "WIN-002": RedisWindowsAuthSequenceRule(
            state_manager=state_manager,
            failure_threshold=sequence_threshold,
            window_seconds=failed_auth_window,
        ),
    }

    # WIN-003 is stateless, use the original
    if enable_privileged_rule:
        rules["WIN-003"] = WindowsPrivilegedActivityRule(enabled=True)

    logger.info(
        "Created Redis-backed Windows rules",
        rules=list(rules.keys()),
        failed_auth_threshold=failed_auth_threshold,
        sequence_threshold=sequence_threshold,
    )

    return rules
