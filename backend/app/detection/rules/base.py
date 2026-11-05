"""
CyberGuard AI - Base Detection Rule

Abstract base class for all detection rules.
Rules can be defined in code or loaded from YAML configuration.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class RuleSeverity(str, Enum):
    """Severity levels for detection rules."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RuleCategory(str, Enum):
    """Categories of detection rules."""
    PHISHING = "phishing"
    MALWARE = "malware"
    BRUTE_FORCE = "brute_force"
    CREDENTIAL_ACCESS = "credential_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    RECONNAISSANCE = "reconnaissance"
    NETWORK_ANOMALY = "network_anomaly"
    POLICY_VIOLATION = "policy_violation"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"


class RuleMatch(BaseModel):
    """Result of a rule match."""

    match_id: str = Field(default_factory=lambda: str(uuid4()))
    rule_id: str = Field(..., description="ID of the matched rule")
    rule_name: str = Field(..., description="Name of the matched rule")
    severity: RuleSeverity = Field(..., description="Severity of the match")
    category: RuleCategory = Field(..., description="Category of the rule")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Match confidence")
    description: str = Field(..., description="Description of what was detected")
    evidence: list[str] = Field(default_factory=list, description="Evidence supporting the match")
    matched_data: dict[str, Any] = Field(default_factory=dict, description="Data that triggered the match")
    mitre_techniques: list[str] = Field(default_factory=list, description="MITRE ATT&CK techniques")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class DetectionRule(ABC):
    """
    Abstract base class for detection rules.

    All rules must implement:
    - evaluate(): Check if data matches the rule

    Rules can be:
    - Pattern-based (regex matching)
    - Threshold-based (count/frequency)
    - Behavioral (sequence analysis)
    - Statistical (anomaly detection)
    """

    rule_id: str
    rule_name: str
    description: str
    severity: RuleSeverity
    category: RuleCategory
    enabled: bool = True
    confidence: float = 0.8
    mitre_techniques: list[str] = []

    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        description: str,
        severity: RuleSeverity,
        category: RuleCategory,
        enabled: bool = True,
        confidence: float = 0.8,
        mitre_techniques: list[str] | None = None,
    ):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.description = description
        self.severity = severity
        self.category = category
        self.enabled = enabled
        self.confidence = confidence
        self.mitre_techniques = mitre_techniques or []

    @abstractmethod
    def evaluate(self, data: dict[str, Any]) -> RuleMatch | None:
        """
        Evaluate data against this rule.

        Args:
            data: Data to evaluate (normalized event, email content, etc.)

        Returns:
            RuleMatch if rule triggers, None otherwise
        """
        pass

    def _create_match(
        self,
        description: str,
        evidence: list[str],
        matched_data: dict[str, Any] | None = None,
        confidence_override: float | None = None,
    ) -> RuleMatch:
        """Helper to create a RuleMatch."""
        return RuleMatch(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            category=self.category,
            confidence=confidence_override or self.confidence,
            description=description,
            evidence=evidence,
            matched_data=matched_data or {},
            mitre_techniques=self.mitre_techniques,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert rule to dictionary."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "enabled": self.enabled,
            "confidence": self.confidence,
            "mitre_techniques": self.mitre_techniques,
        }


class PatternRule(DetectionRule):
    """
    Pattern-based detection rule using regex matching.
    """

    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        description: str,
        severity: RuleSeverity,
        category: RuleCategory,
        patterns: list[str],
        fields: list[str],
        match_all: bool = False,
        **kwargs,
    ):
        super().__init__(rule_id, rule_name, description, severity, category, **kwargs)
        import re
        self.patterns = [re.compile(p, re.IGNORECASE) for p in patterns]
        self.fields = fields
        self.match_all = match_all  # True = AND, False = OR

    def evaluate(self, data: dict[str, Any]) -> RuleMatch | None:
        """Evaluate data against patterns."""
        if not self.enabled:
            return None

        matches_found = []

        for field in self.fields:
            value = data.get(field, "")
            if not isinstance(value, str):
                value = str(value)

            for pattern in self.patterns:
                match = pattern.search(value)
                if match:
                    matches_found.append({
                        "field": field,
                        "pattern": pattern.pattern,
                        "matched": match.group(),
                    })

        # Check if we have enough matches
        if self.match_all:
            if len(matches_found) < len(self.patterns):
                return None
        else:
            if not matches_found:
                return None

        evidence = [f"Field '{m['field']}' matched pattern: {m['matched']}" for m in matches_found]

        return self._create_match(
            description=f"{self.rule_name}: Pattern match detected",
            evidence=evidence,
            matched_data={"matches": matches_found},
        )


class ThresholdRule(DetectionRule):
    """
    Threshold-based detection rule.
    Triggers when count/frequency exceeds threshold.
    """

    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        description: str,
        severity: RuleSeverity,
        category: RuleCategory,
        count_field: str,
        threshold: int,
        comparison: str = ">=",  # >=, >, ==, <, <=
        **kwargs,
    ):
        super().__init__(rule_id, rule_name, description, severity, category, **kwargs)
        self.count_field = count_field
        self.threshold = threshold
        self.comparison = comparison

    def evaluate(self, data: dict[str, Any]) -> RuleMatch | None:
        """Evaluate data against threshold."""
        if not self.enabled:
            return None

        count = data.get(self.count_field, 0)
        if not isinstance(count, (int, float)):
            return None

        triggered = False
        if self.comparison == ">=" and count >= self.threshold:
            triggered = True
        elif self.comparison == ">" and count > self.threshold:
            triggered = True
        elif self.comparison == "==" and count == self.threshold:
            triggered = True
        elif self.comparison == "<" and count < self.threshold:
            triggered = True
        elif self.comparison == "<=" and count <= self.threshold:
            triggered = True

        if not triggered:
            return None

        return self._create_match(
            description=f"{self.rule_name}: {self.count_field}={count} {self.comparison} {self.threshold}",
            evidence=[f"{self.count_field}: {count} (threshold: {self.comparison} {self.threshold})"],
            matched_data={"field": self.count_field, "value": count, "threshold": self.threshold},
        )
