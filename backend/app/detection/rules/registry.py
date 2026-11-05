"""
CyberGuard AI - Rule Registry

Manages registration and lookup of detection rules.
"""

from typing import Any
import structlog

from app.detection.rules.base import (
    DetectionRule,
    PatternRule,
    ThresholdRule,
    RuleMatch,
    RuleSeverity,
    RuleCategory,
)


logger = structlog.get_logger(__name__)


class RuleRegistry:
    """
    Central registry for all detection rules.

    Provides:
    - Rule registration
    - Rule lookup by ID, category, severity
    - Bulk rule evaluation
    - Rule statistics
    """

    def __init__(self):
        self._rules: dict[str, DetectionRule] = {}
        self._rules_by_category: dict[RuleCategory, list[str]] = {}
        self._initialize_default_rules()

    def _initialize_default_rules(self) -> None:
        """Initialize built-in detection rules."""
        # Email-related rules
        self.register(PatternRule(
            rule_id="RULE-EMAIL-001",
            rule_name="Urgency Language Pattern",
            description="Detects urgency tactics commonly used in phishing",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.PHISHING,
            patterns=[
                r"urgent",
                r"immediate\s+action",
                r"act\s+now",
                r"within\s+\d+\s+hours?",
            ],
            fields=["subject", "body"],
            match_all=False,
            mitre_techniques=["T1566.001"],
        ))

        self.register(PatternRule(
            rule_id="RULE-EMAIL-002",
            rule_name="Credential Request Pattern",
            description="Detects requests for credentials or sensitive information",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.CREDENTIAL_ACCESS,
            patterns=[
                r"enter\s+(your\s+)?(password|credentials)",
                r"verify\s+(your\s+)?(account|identity)",
                r"confirm\s+(your\s+)?(password|account)",
            ],
            fields=["subject", "body"],
            match_all=False,
            mitre_techniques=["T1566.001", "T1598"],
        ))

        self.register(PatternRule(
            rule_id="RULE-EMAIL-003",
            rule_name="Account Suspension Threat",
            description="Detects threats of account suspension/termination",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.PHISHING,
            patterns=[
                r"account\s+(will\s+be\s+)?(suspend|terminat|block|lock)",
                r"failure\s+to\s+(verify|respond|confirm)",
            ],
            fields=["subject", "body"],
            match_all=False,
            mitre_techniques=["T1566.001"],
        ))

        # Log-related rules
        self.register(ThresholdRule(
            rule_id="RULE-LOG-001",
            rule_name="Multiple Authentication Failures",
            description="Detects multiple failed authentication attempts",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.BRUTE_FORCE,
            count_field="auth_failure_count",
            threshold=5,
            comparison=">=",
            mitre_techniques=["T1110.001"],
        ))

        self.register(ThresholdRule(
            rule_id="RULE-LOG-002",
            rule_name="Credential Stuffing Pattern",
            description="Detects attempts with many different usernames",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.CREDENTIAL_ACCESS,
            count_field="unique_failed_users",
            threshold=10,
            comparison=">=",
            mitre_techniques=["T1110.004"],
        ))

        self.register(PatternRule(
            rule_id="RULE-LOG-003",
            rule_name="Privilege Escalation Attempt",
            description="Detects potential privilege escalation commands",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.PRIVILEGE_ESCALATION,
            patterns=[
                r"sudo\s+su\s*$",
                r"sudo\s+bash",
                r"sudo\s+passwd",
                r"chmod\s+777",
                r"chmod\s+4755",
            ],
            fields=["command", "raw"],
            match_all=False,
            mitre_techniques=["T1548.003"],
        ))

        # Network-related rules
        self.register(PatternRule(
            rule_id="RULE-NET-001",
            rule_name="Database Port Exposed",
            description="Detects exposed database ports",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.RECONNAISSANCE,
            patterns=[
                r"port:\s*(3306|5432|1433|27017|6379)",
            ],
            fields=["scan_results", "ports"],
            match_all=False,
            mitre_techniques=["T1046"],
        ))

        logger.info("Default rules initialized", rule_count=len(self._rules))

    def register(self, rule: DetectionRule) -> None:
        """Register a detection rule."""
        if rule.rule_id in self._rules:
            logger.warning("Overwriting existing rule", rule_id=rule.rule_id)

        self._rules[rule.rule_id] = rule

        # Index by category
        if rule.category not in self._rules_by_category:
            self._rules_by_category[rule.category] = []
        if rule.rule_id not in self._rules_by_category[rule.category]:
            self._rules_by_category[rule.category].append(rule.rule_id)

        logger.debug("Rule registered", rule_id=rule.rule_id, rule_name=rule.rule_name)

    def unregister(self, rule_id: str) -> bool:
        """Unregister a rule."""
        if rule_id not in self._rules:
            return False

        rule = self._rules.pop(rule_id)

        # Remove from category index
        if rule.category in self._rules_by_category:
            if rule_id in self._rules_by_category[rule.category]:
                self._rules_by_category[rule.category].remove(rule_id)

        return True

    def get(self, rule_id: str) -> DetectionRule | None:
        """Get a rule by ID."""
        return self._rules.get(rule_id)

    def get_by_category(self, category: RuleCategory) -> list[DetectionRule]:
        """Get all rules in a category."""
        rule_ids = self._rules_by_category.get(category, [])
        return [self._rules[rid] for rid in rule_ids if rid in self._rules]

    def get_all(self, enabled_only: bool = True) -> list[DetectionRule]:
        """Get all rules."""
        rules = list(self._rules.values())
        if enabled_only:
            rules = [r for r in rules if r.enabled]
        return rules

    def evaluate_all(
        self,
        data: dict[str, Any],
        categories: list[RuleCategory] | None = None,
    ) -> list[RuleMatch]:
        """
        Evaluate data against all applicable rules.

        Args:
            data: Data to evaluate
            categories: Optional filter by categories

        Returns:
            List of rule matches
        """
        matches = []

        rules = self.get_all(enabled_only=True)
        if categories:
            rules = [r for r in rules if r.category in categories]

        for rule in rules:
            try:
                match = rule.evaluate(data)
                if match:
                    matches.append(match)
            except Exception as e:
                logger.error(
                    "Rule evaluation error",
                    rule_id=rule.rule_id,
                    error=str(e),
                )

        return matches

    def get_statistics(self) -> dict[str, Any]:
        """Get rule statistics."""
        total = len(self._rules)
        enabled = sum(1 for r in self._rules.values() if r.enabled)
        by_category = {
            cat.value: len(rules)
            for cat, rules in self._rules_by_category.items()
        }
        by_severity = {}
        for rule in self._rules.values():
            sev = rule.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1

        return {
            "total_rules": total,
            "enabled_rules": enabled,
            "disabled_rules": total - enabled,
            "by_category": by_category,
            "by_severity": by_severity,
        }


# Singleton instance
_registry: RuleRegistry | None = None


def get_rule_registry() -> RuleRegistry:
    """Get the global rule registry."""
    global _registry
    if _registry is None:
        _registry = RuleRegistry()
    return _registry
