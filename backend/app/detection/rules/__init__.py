"""CyberGuard AI - Detection Rules Package"""

from app.detection.rules.base import (
    DetectionRule,
    PatternRule,
    ThresholdRule,
    RuleMatch,
    RuleSeverity,
    RuleCategory,
)
from app.detection.rules.registry import RuleRegistry, get_rule_registry
from app.detection.rules.windows import (
    WindowsFailedAuthBurstRule,
    WindowsAuthSequenceRule,
    WindowsPrivilegedActivityRule,
    register_windows_rules,
    get_windows_failed_auth_rule,
    get_windows_auth_sequence_rule,
    get_windows_privileged_rule,
    DEFAULT_FAILED_AUTH_THRESHOLD,
    DEFAULT_FAILED_AUTH_WINDOW_SECONDS,
    DEFAULT_SEQUENCE_FAILURE_THRESHOLD,
)
from app.detection.rules.windows_redis import (
    RedisWindowsFailedAuthBurstRule,
    RedisWindowsAuthSequenceRule,
    create_redis_windows_rules,
)

__all__ = [
    # Base
    "DetectionRule",
    "PatternRule",
    "ThresholdRule",
    "RuleMatch",
    "RuleSeverity",
    "RuleCategory",
    "RuleRegistry",
    "get_rule_registry",
    # Windows rules (STEP 8.2) - In-memory
    "WindowsFailedAuthBurstRule",
    "WindowsAuthSequenceRule",
    "WindowsPrivilegedActivityRule",
    "register_windows_rules",
    "get_windows_failed_auth_rule",
    "get_windows_auth_sequence_rule",
    "get_windows_privileged_rule",
    "DEFAULT_FAILED_AUTH_THRESHOLD",
    "DEFAULT_FAILED_AUTH_WINDOW_SECONDS",
    "DEFAULT_SEQUENCE_FAILURE_THRESHOLD",
    # Redis-backed Windows rules (STEP 8.2.1)
    "RedisWindowsFailedAuthBurstRule",
    "RedisWindowsAuthSequenceRule",
    "create_redis_windows_rules",
]
