"""
CyberGuard AI - Security Event Logger

Dedicated logger for security-relevant events.
All security events use a dedicated "security" logger for easy filtering/routing.

Security events include:
- Threat detection
- Malware detection
- Authentication failures
- Suspicious URLs
- Rate limit violations
- Circuit breaker state changes
"""

import structlog
from typing import Optional, Any


# Dedicated security logger
security_logger = structlog.get_logger("security")


def log_threat_detected(
    *,
    email_id: Optional[str] = None,
    classification: str,
    risk_score: int,
    finding_count: int,
    finding_types: Optional[list[str]] = None,
    sender_domain: Optional[str] = None,
    request_id: Optional[str] = None,
) -> None:
    """
    Log a threat detection event.

    Args:
        email_id: Anonymized email identifier (NOT the full email)
        classification: Verdict (phishing, malicious, suspicious, etc.)
        risk_score: Calculated risk score
        finding_count: Number of findings
        finding_types: List of finding rule IDs or categories
        sender_domain: Domain part of sender (NOT full address)
        request_id: Request tracing ID
    """
    security_logger.warning(
        "threat_detected",
        event_type="threat_detected",
        email_id=email_id,
        classification=classification,
        risk_score=risk_score,
        finding_count=finding_count,
        finding_types=finding_types or [],
        sender_domain=sender_domain,
        request_id=request_id,
    )


def log_malware_detected(
    *,
    filename: str,
    sha256: str,
    detection_source: str,
    threat_names: Optional[list[str]] = None,
    email_id: Optional[str] = None,
    request_id: Optional[str] = None,
) -> None:
    """
    Log a malware detection event.

    Args:
        filename: Name of the malicious file
        sha256: SHA256 hash of the file
        detection_source: Source of detection (virustotal, local, etc.)
        threat_names: Names of detected threats
        email_id: Associated email identifier
        request_id: Request tracing ID
    """
    security_logger.critical(
        "malware_detected",
        event_type="malware_detected",
        filename=filename,
        sha256=sha256,
        detection_source=detection_source,
        threat_names=threat_names or [],
        email_id=email_id,
        request_id=request_id,
    )


def log_auth_failure(
    *,
    email_id: Optional[str] = None,
    sender_domain: str,
    spf: str,
    dkim: str,
    dmarc: str,
    request_id: Optional[str] = None,
) -> None:
    """
    Log an email authentication failure event.

    Args:
        email_id: Anonymized email identifier
        sender_domain: Domain being authenticated
        spf: SPF result (pass/fail/none/etc.)
        dkim: DKIM result
        dmarc: DMARC result
        request_id: Request tracing ID
    """
    security_logger.warning(
        "email_auth_failure",
        event_type="email_auth_failure",
        email_id=email_id,
        sender_domain=sender_domain,
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        request_id=request_id,
    )


def log_suspicious_url(
    *,
    domain: str,
    detection_source: str,
    risk_score: Optional[int] = None,
    severity: Optional[str] = None,
    email_id: Optional[str] = None,
    request_id: Optional[str] = None,
) -> None:
    """
    Log a suspicious URL detection event.

    Args:
        domain: Domain of the suspicious URL (NOT full URL with query params)
        detection_source: Source of detection (safe_browsing, virustotal, pattern, etc.)
        risk_score: Risk score if available
        severity: Severity level
        email_id: Associated email identifier
        request_id: Request tracing ID
    """
    security_logger.warning(
        "suspicious_url",
        event_type="suspicious_url",
        domain=domain,
        detection_source=detection_source,
        risk_score=risk_score,
        severity=severity,
        email_id=email_id,
        request_id=request_id,
    )


def log_rate_limit_exceeded(
    *,
    endpoint: str,
    client_ip: Optional[str] = None,
    limit: str,
    request_id: Optional[str] = None,
) -> None:
    """
    Log a rate limit exceeded event.

    Args:
        endpoint: The rate-limited endpoint path
        client_ip: Client IP address (if appropriate to log)
        limit: The configured limit that was exceeded
        request_id: Request tracing ID
    """
    security_logger.warning(
        "rate_limit_exceeded",
        event_type="rate_limit_exceeded",
        endpoint=endpoint,
        client_ip=client_ip,
        limit=limit,
        request_id=request_id,
    )


def log_circuit_opened(
    *,
    service_name: str,
    state: str,
    failure_count: int,
    reason: Optional[str] = None,
) -> None:
    """
    Log a circuit breaker state change event.

    Args:
        service_name: Name of the affected service
        state: New circuit state (open, half_open, closed)
        failure_count: Number of failures that triggered the change
        reason: Optional reason for the state change
    """
    security_logger.warning(
        "circuit_opened",
        event_type="circuit_opened",
        service_name=service_name,
        state=state,
        failure_count=failure_count,
        reason=reason,
    )


def log_circuit_recovered(
    *,
    service_name: str,
    state: str,
) -> None:
    """
    Log a circuit breaker recovery event.

    Args:
        service_name: Name of the recovered service
        state: New circuit state (should be 'closed')
    """
    security_logger.info(
        "circuit_recovered",
        event_type="circuit_recovered",
        service_name=service_name,
        state=state,
    )
