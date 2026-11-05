"""
CyberGuard AI - Log Analyzer Agent

Specialized agent for detecting suspicious patterns and
security threats in system and authentication logs.

Supported Log Formats:
- Linux auth logs (syslog format)
- SSH authentication logs
- Web server logs (Apache/Nginx common format)
- Generic syslog format

Detection Methods:
1. Authentication failure analysis
2. Brute-force detection (multiple failures from same source)
3. Successful login after failures (potential compromise)
4. Privilege escalation detection (sudo/su)
5. Suspicious user behavior
6. Time-based anomalies
7. IOC extraction (IPs, users, hostnames)
8. Sequence analysis

Classification Output:
- benign: Normal activity
- suspicious: Some indicators present
- malicious: Clear security threat patterns
"""

import re
from datetime import datetime, timedelta
from typing import Any
from collections import defaultdict

from app.agents.base import (
    BaseAgent,
    AgentType,
    AgentStatus,
    AgentResult,
    Finding,
    Severity,
)


# =============================================================================
# Log Patterns
# =============================================================================

# SSH/Auth log patterns
SSH_FAILED_PASSWORD = re.compile(
    r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+sshd\[(\d+)\]:\s+Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)',
    re.IGNORECASE
)

SSH_ACCEPTED_PASSWORD = re.compile(
    r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+sshd\[(\d+)\]:\s+Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)',
    re.IGNORECASE
)

SSH_INVALID_USER = re.compile(
    r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+sshd\[(\d+)\]:\s+Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)',
    re.IGNORECASE
)

# Sudo patterns
SUDO_COMMAND = re.compile(
    r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+sudo:\s+(\S+)\s+:.*COMMAND=(.*)',
    re.IGNORECASE
)

SUDO_FAILED = re.compile(
    r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+sudo:\s+(\S+)\s+:.*authentication failure',
    re.IGNORECASE
)

# Generic auth patterns
AUTH_FAILURE_GENERIC = re.compile(
    r'authentication fail|auth.*fail|login.*fail|invalid password|bad password',
    re.IGNORECASE
)

AUTH_SUCCESS_GENERIC = re.compile(
    r'authentication success|auth.*success|login.*success|session opened',
    re.IGNORECASE
)

# IP address extraction
IP_PATTERN = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

# Username patterns (common in logs)
USER_PATTERN = re.compile(r'(?:user|for|by)\s+["\']?(\w+)["\']?', re.IGNORECASE)


# =============================================================================
# Thresholds
# =============================================================================

BRUTE_FORCE_THRESHOLD = 5  # Failed attempts to trigger brute force alert
BRUTE_FORCE_WINDOW_SECONDS = 300  # 5 minute window
SUSPICIOUS_SUCCESS_AFTER_FAILURES = 3  # Alert if success after this many failures


# =============================================================================
# Log Analyzer Agent
# =============================================================================

class LogAgent(BaseAgent):
    """
    Log Analyzer Agent for detecting security threats in system logs.
    """

    agent_type = AgentType.LOG
    agent_name = "Log Analyzer Agent"
    agent_version = "0.1.0"

    def __init__(self):
        super().__init__()
        self._status = AgentStatus.ONLINE

    async def validate(self, data: dict[str, Any]) -> tuple[bool, str | None]:
        """Validate log data."""
        log_content = data.get("log_content", "")
        if not log_content or not log_content.strip():
            return False, "Log content is required"

        lines = [l for l in log_content.strip().split("\n") if l.strip()]
        if len(lines) == 0:
            return False, "Log content must contain at least one log entry"

        return True, None

    async def analyze(self, data: dict[str, Any]) -> AgentResult:
        """Analyze logs for security threats."""
        log_content = data.get("log_content", "")
        log_type = data.get("log_type", "auto")
        source_host = data.get("source_host", "unknown")

        # Parse log lines
        lines = [l.strip() for l in log_content.strip().split("\n") if l.strip()]

        # Extract events
        events = self._parse_log_events(lines)

        # Run detection methods
        auth_failures_findings = self._detect_auth_failures(events)
        brute_force_findings = self._detect_brute_force(events)

        # LOG-001 (>=3 auth failures/IP) and LOG-002/003 (>=5/IP) scan the
        # same auth_failure population independently, so any IP with >=5
        # plain auth failures satisfies both and used to produce two
        # overlapping findings for the same underlying failures. Once the
        # higher-severity brute-force finding fires for an IP, drop the
        # lower-severity auth-failures finding for that same IP instead of
        # reporting both.
        brute_force_ips = {f.source_ip for f in brute_force_findings if f.source_ip}
        auth_failures_findings = [
            f for f in auth_failures_findings if f.source_ip not in brute_force_ips
        ]

        findings: list[Finding] = []
        findings.extend(auth_failures_findings)
        findings.extend(brute_force_findings)
        findings.extend(self._detect_compromise_pattern(events))
        findings.extend(self._detect_privilege_escalation(events))
        findings.extend(self._detect_invalid_users(events))

        # Extract IOCs
        indicators = self._extract_iocs(events)

        # Calculate risk
        classification, severity, confidence, risk_score = self._calculate_risk(findings, events)

        # Generate recommendations
        recommendations = self._generate_recommendations(findings, classification)

        # Build summary
        summary = self._build_summary(classification, findings, events, indicators)

        # Affected systems/accounts: union of real, non-null source_ip/host
        # values across findings, and real usernames pulled from the
        # underlying events for findings that implicate specific accounts.
        # Empty when nothing was actually extracted - never a placeholder.
        affected_systems = sorted({
            value
            for f in findings
            for value in (f.source_ip, f.host)
            if value
        })
        affected_accounts = sorted({
            e.get("user")
            for e in events
            if e.get("user") and e.get("event_type") in ("auth_failure", "invalid_user")
        })

        return self._create_result(
            classification=classification,
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            findings=findings,
            summary=summary,
            indicators=indicators,
            recommendations=recommendations,
            source=log_type if log_type and log_type != "auto" else None,
            processed_event_count=len(events),
            affected_systems=affected_systems,
            affected_accounts=affected_accounts,
        )

    # -------------------------------------------------------------------------
    # Event Parsing
    # -------------------------------------------------------------------------

    def _parse_log_events(self, lines: list[str]) -> list[dict[str, Any]]:
        """Parse log lines into structured events."""
        events = []

        for i, line in enumerate(lines):
            event = {
                "line_number": i + 1,
                "raw": line,
                "event_type": "unknown",
                "timestamp": None,
                "host": None,
                "user": None,
                "source_ip": None,
                "success": None,
            }

            # Try SSH failed password
            match = SSH_FAILED_PASSWORD.search(line)
            if match:
                event.update({
                    "event_type": "auth_failure",
                    "timestamp": match.group(1),
                    "host": match.group(2),
                    "user": match.group(4),
                    "source_ip": match.group(5),
                    "success": False,
                    "service": "ssh",
                })
                events.append(event)
                continue

            # Try SSH accepted
            match = SSH_ACCEPTED_PASSWORD.search(line)
            if match:
                event.update({
                    "event_type": "auth_success",
                    "timestamp": match.group(1),
                    "host": match.group(2),
                    "user": match.group(4),
                    "source_ip": match.group(5),
                    "success": True,
                    "service": "ssh",
                })
                events.append(event)
                continue

            # Try SSH invalid user
            match = SSH_INVALID_USER.search(line)
            if match:
                event.update({
                    "event_type": "invalid_user",
                    "timestamp": match.group(1),
                    "host": match.group(2),
                    "user": match.group(4),
                    "source_ip": match.group(5),
                    "success": False,
                    "service": "ssh",
                })
                events.append(event)
                continue

            # Try sudo command
            match = SUDO_COMMAND.search(line)
            if match:
                event.update({
                    "event_type": "sudo_command",
                    "timestamp": match.group(1),
                    "host": match.group(2),
                    "user": match.group(3),
                    "command": match.group(4),
                    "service": "sudo",
                })
                events.append(event)
                continue

            # Try sudo failure
            match = SUDO_FAILED.search(line)
            if match:
                event.update({
                    "event_type": "sudo_failure",
                    "timestamp": match.group(1),
                    "host": match.group(2),
                    "user": match.group(3),
                    "success": False,
                    "service": "sudo",
                })
                events.append(event)
                continue

            # Try generic patterns
            if AUTH_FAILURE_GENERIC.search(line):
                # Extract IP if present
                ip_match = IP_PATTERN.search(line)
                user_match = USER_PATTERN.search(line)
                event.update({
                    "event_type": "auth_failure",
                    "source_ip": ip_match.group(1) if ip_match else None,
                    "user": user_match.group(1) if user_match else None,
                    "success": False,
                })
                events.append(event)
                continue

            if AUTH_SUCCESS_GENERIC.search(line):
                ip_match = IP_PATTERN.search(line)
                user_match = USER_PATTERN.search(line)
                event.update({
                    "event_type": "auth_success",
                    "source_ip": ip_match.group(1) if ip_match else None,
                    "user": user_match.group(1) if user_match else None,
                    "success": True,
                })
                events.append(event)
                continue

            # If nothing matched but has IP, still record
            ip_match = IP_PATTERN.search(line)
            if ip_match:
                event["source_ip"] = ip_match.group(1)
                events.append(event)

        return events

    # -------------------------------------------------------------------------
    # Detection Methods
    # -------------------------------------------------------------------------

    def _detect_auth_failures(self, events: list[dict]) -> list[Finding]:
        """Detect authentication failures."""
        findings = []

        failures = [e for e in events if e.get("event_type") == "auth_failure"]

        if not failures:
            return findings

        # Group by source IP
        by_ip = defaultdict(list)
        for f in failures:
            if f.get("source_ip"):
                by_ip[f["source_ip"]].append(f)

        for ip, ip_failures in by_ip.items():
            if len(ip_failures) >= 3:
                users = list(set(f.get("user", "unknown") for f in ip_failures))
                findings.append(Finding(
                    rule_id="LOG-001",
                    name="Multiple authentication failures",
                    description=f"Multiple failed login attempts from IP {ip}",
                    severity=Severity.MEDIUM,
                    confidence=0.8,
                    evidence=[
                        f"Source IP: {ip}",
                        f"Failed attempts: {len(ip_failures)}",
                        f"Targeted users: {', '.join(users[:5])}",
                    ],
                    mitre_techniques=["T1110.001"],
                    recommendations=[
                        f"Investigate activity from IP {ip}",
                        "Consider blocking IP if not legitimate",
                    ],
                    source_ip=ip,
                    host=ip_failures[0].get("host"),
                    timestamp=ip_failures[-1].get("timestamp"),
                ))

        return findings

    def _detect_brute_force(self, events: list[dict]) -> list[Finding]:
        """Detect brute force attack patterns."""
        findings = []

        failures = [e for e in events if e.get("event_type") in ("auth_failure", "invalid_user")]

        # Group by source IP
        by_ip = defaultdict(list)
        for f in failures:
            if f.get("source_ip"):
                by_ip[f["source_ip"]].append(f)

        for ip, ip_failures in by_ip.items():
            if len(ip_failures) >= BRUTE_FORCE_THRESHOLD:
                # Check for multiple different usernames (credential stuffing)
                unique_users = set(f.get("user") for f in ip_failures if f.get("user"))

                if len(unique_users) > 3:
                    # Credential stuffing - trying many usernames
                    findings.append(Finding(
                        rule_id="LOG-002",
                        name="Potential credential stuffing attack",
                        description=f"Multiple failed attempts with different usernames from {ip}",
                        severity=Severity.HIGH,
                        confidence=0.85,
                        evidence=[
                            f"Source IP: {ip}",
                            f"Failed attempts: {len(ip_failures)}",
                            f"Unique usernames tried: {len(unique_users)}",
                            f"Usernames: {', '.join(list(unique_users)[:5])}...",
                        ],
                        mitre_techniques=["T1110.004"],
                        recommendations=[
                            f"Block IP {ip} immediately",
                            "Enable account lockout policies",
                            "Check if any accounts were compromised",
                        ],
                        source_ip=ip,
                        host=ip_failures[0].get("host"),
                        timestamp=ip_failures[-1].get("timestamp"),
                    ))
                else:
                    # Standard brute force - targeting specific user(s)
                    findings.append(Finding(
                        rule_id="LOG-003",
                        name="Potential brute force attack",
                        description=f"Brute force attack detected from {ip}",
                        severity=Severity.HIGH,
                        confidence=0.9,
                        evidence=[
                            f"Source IP: {ip}",
                            f"Failed attempts: {len(ip_failures)}",
                            f"Target user(s): {', '.join(unique_users)}",
                        ],
                        mitre_techniques=["T1110.001"],
                        recommendations=[
                            f"Block IP {ip}",
                            "Reset password for targeted user(s)",
                            "Enable MFA if not already enabled",
                        ],
                        source_ip=ip,
                        host=ip_failures[0].get("host"),
                        timestamp=ip_failures[-1].get("timestamp"),
                    ))

        return findings

    def _detect_compromise_pattern(self, events: list[dict]) -> list[Finding]:
        """Detect successful login after multiple failures (potential compromise)."""
        findings = []

        # Group events by source IP
        by_ip = defaultdict(list)
        for e in events:
            if e.get("source_ip"):
                by_ip[e["source_ip"]].append(e)

        for ip, ip_events in by_ip.items():
            failures_before_success = 0
            target_user = None

            for event in ip_events:
                if event.get("event_type") in ("auth_failure", "invalid_user"):
                    failures_before_success += 1
                    target_user = event.get("user")
                elif event.get("event_type") == "auth_success":
                    if failures_before_success >= SUSPICIOUS_SUCCESS_AFTER_FAILURES:
                        findings.append(Finding(
                            rule_id="LOG-004",
                            name="Suspicious successful login after failures",
                            description=f"Successful login from {ip} after {failures_before_success} failed attempts",
                            severity=Severity.CRITICAL,
                            confidence=0.9,
                            evidence=[
                                f"Source IP: {ip}",
                                f"Failed attempts before success: {failures_before_success}",
                                f"User: {event.get('user', target_user or 'unknown')}",
                            ],
                            mitre_techniques=["T1110", "T1078"],
                            recommendations=[
                                "Immediately investigate this access",
                                "Check for unauthorized activities by this user",
                                "Force password reset",
                                "Review session for suspicious commands",
                            ],
                            source_ip=ip,
                            host=event.get("host"),
                            timestamp=event.get("timestamp"),
                        ))
                    failures_before_success = 0

        return findings

    def _detect_privilege_escalation(self, events: list[dict]) -> list[Finding]:
        """Detect privilege escalation attempts."""
        findings = []

        sudo_events = [e for e in events if e.get("event_type") in ("sudo_command", "sudo_failure")]

        if not sudo_events:
            return findings

        # Check for sudo failures
        sudo_failures = [e for e in sudo_events if e.get("event_type") == "sudo_failure"]
        if len(sudo_failures) >= 3:
            users = set(e.get("user") for e in sudo_failures if e.get("user"))
            findings.append(Finding(
                rule_id="LOG-005",
                name="Multiple sudo authentication failures",
                description="Multiple failed sudo attempts detected",
                severity=Severity.MEDIUM,
                confidence=0.75,
                evidence=[
                    f"Failed sudo attempts: {len(sudo_failures)}",
                    f"Users involved: {', '.join(users)}",
                ],
                mitre_techniques=["T1548"],
                recommendations=[
                    "Verify these users should have sudo access",
                    "Check for unauthorized privilege escalation attempts",
                ],
                # No source_ip: sudo events never populate source_ip in
                # _parse_log_events (sudo lines have no IP to extract).
                host=sudo_failures[0].get("host"),
                timestamp=sudo_failures[-1].get("timestamp"),
            ))

        # Check for sensitive sudo commands
        sensitive_commands = ["passwd", "useradd", "usermod", "visudo", "chmod 777", "rm -rf"]
        for event in sudo_events:
            if event.get("event_type") == "sudo_command":
                command = event.get("command", "").lower()
                for sensitive in sensitive_commands:
                    if sensitive in command:
                        findings.append(Finding(
                            rule_id="LOG-006",
                            name="Sensitive command executed",
                            description=f"Potentially sensitive sudo command detected",
                            severity=Severity.MEDIUM,
                            confidence=0.7,
                            evidence=[
                                f"User: {event.get('user', 'unknown')}",
                                f"Command: {event.get('command', 'unknown')}",
                            ],
                            mitre_techniques=["T1548.003"],
                            recommendations=[
                                "Verify this command was authorized",
                                "Review user's sudo permissions",
                            ],
                            # No source_ip: sudo events never populate
                            # source_ip in _parse_log_events.
                            host=event.get("host"),
                            timestamp=event.get("timestamp"),
                        ))
                        break

        return findings

    def _detect_invalid_users(self, events: list[dict]) -> list[Finding]:
        """Detect attempts with invalid/non-existent users."""
        findings = []

        invalid_user_events = [e for e in events if e.get("event_type") == "invalid_user"]

        if len(invalid_user_events) >= 3:
            users = list(set(e.get("user", "unknown") for e in invalid_user_events))
            ips = list(set(e.get("source_ip", "unknown") for e in invalid_user_events if e.get("source_ip")))

            findings.append(Finding(
                rule_id="LOG-007",
                name="Multiple invalid user attempts",
                description="Attempts to login with non-existent usernames",
                severity=Severity.MEDIUM,
                confidence=0.8,
                evidence=[
                    f"Invalid usernames tried: {', '.join(users[:10])}",
                    f"Source IPs: {', '.join(ips[:5])}",
                    f"Total attempts: {len(invalid_user_events)}",
                ],
                mitre_techniques=["T1078.001", "T1110.001"],
                recommendations=[
                    "This may indicate username enumeration",
                    "Consider blocking source IPs",
                    "Review authentication logs for patterns",
                ],
                # Multiple IPs can be involved; use the first as the
                # representative source_ip rather than fabricating a
                # single-value field this finding doesn't really have.
                source_ip=ips[0] if ips else None,
                host=invalid_user_events[0].get("host"),
                timestamp=invalid_user_events[-1].get("timestamp"),
            ))

        return findings

    # -------------------------------------------------------------------------
    # Helper Methods
    # -------------------------------------------------------------------------

    def _extract_iocs(self, events: list[dict]) -> list[str]:
        """Extract IOCs from events."""
        iocs = set()

        for event in events:
            if event.get("source_ip"):
                iocs.add(event["source_ip"])
            if event.get("user") and event.get("event_type") in ("auth_failure", "invalid_user"):
                # Only add users involved in suspicious activity
                iocs.add(f"user:{event['user']}")

        return list(iocs)

    def _calculate_risk(self, findings: list[Finding], events: list[dict]) -> tuple[str, Severity, float, int]:
        """Calculate overall risk."""
        if not findings:
            return "benign", Severity.INFO, 0.95, 5

        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        medium_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)

        # Calculate risk score
        risk_score = min(100, (
            critical_count * 35 +
            high_count * 20 +
            medium_count * 8 +
            len(findings) * 3
        ))

        # Determine classification
        if critical_count > 0 or risk_score >= 80:
            classification = "malicious"
            severity = Severity.CRITICAL
            confidence = min(0.95, 0.75 + critical_count * 0.1)
        elif high_count > 0 or risk_score >= 50:
            classification = "malicious"
            severity = Severity.HIGH
            confidence = min(0.9, 0.65 + high_count * 0.1)
        elif medium_count > 0 or risk_score >= 25:
            classification = "suspicious"
            severity = Severity.MEDIUM
            confidence = 0.7
        else:
            classification = "suspicious"
            severity = Severity.LOW
            confidence = 0.6

        return classification, severity, confidence, risk_score

    def _generate_recommendations(self, findings: list[Finding], classification: str) -> list[str]:
        """Generate recommendations."""
        recommendations = []

        if classification == "malicious":
            recommendations.extend([
                "Immediately investigate the affected systems",
                "Block suspicious IP addresses at the firewall",
                "Reset credentials for targeted accounts",
                "Enable or review MFA settings",
            ])
        elif classification == "suspicious":
            recommendations.extend([
                "Review authentication logs for additional context",
                "Verify if activity is from legitimate users",
                "Consider implementing rate limiting",
            ])

        # Add unique recommendations from findings
        for finding in findings:
            for rec in finding.recommendations:
                if rec not in recommendations:
                    recommendations.append(rec)

        return recommendations[:10]

    def _build_summary(self, classification: str, findings: list[Finding], events: list[dict], indicators: list[str]) -> str:
        """Build summary."""
        if classification == "benign":
            return f"Analyzed {len(events)} log entries. No significant security threats detected."

        finding_names = ", ".join(f.name for f in findings[:3])
        if len(findings) > 3:
            finding_names += f" and {len(findings) - 3} more"

        auth_failures = sum(1 for e in events if e.get("event_type") == "auth_failure")
        auth_successes = sum(1 for e in events if e.get("event_type") == "auth_success")

        return (
            f"Analyzed {len(events)} log entries. "
            f"Classification: {classification.upper()}. "
            f"Found {auth_failures} auth failures, {auth_successes} successes. "
            f"Detected {len(findings)} security indicator(s): {finding_names}. "
            f"Extracted {len(indicators)} IOC(s)."
        )
