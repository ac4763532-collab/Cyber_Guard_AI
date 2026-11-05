"""
CyberGuard AI - Logging Module

Security event logging utilities.
"""

from app.logging.security_events import (
    log_threat_detected,
    log_malware_detected,
    log_auth_failure,
    log_suspicious_url,
    log_rate_limit_exceeded,
    log_circuit_opened,
    log_circuit_recovered,
    security_logger,
)

__all__ = [
    "log_threat_detected",
    "log_malware_detected",
    "log_auth_failure",
    "log_suspicious_url",
    "log_rate_limit_exceeded",
    "log_circuit_opened",
    "log_circuit_recovered",
    "security_logger",
]
