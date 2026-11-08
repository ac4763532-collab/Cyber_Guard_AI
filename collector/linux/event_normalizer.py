"""
CyberGuard AI Collector — Security Event Normalizer
"""
from datetime import datetime, timezone
import socket
from typing import Dict, Any

def normalize_event(
    event_type: str,
    severity: str = "informational",
    category: str = "endpoint",
    action: str = "logon",
    outcome: str = "success",
    username: str = None,
    source_ip: str = None,
    process_name: str = None,
    details: Dict[str, Any] = None
) -> Dict[str, Any]:
    return {
        "event_time": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "category": category,
        "event_type": event_type,
        "action": action,
        "outcome": outcome,
        "hostname": socket.gethostname(),
        "username": username,
        "source_ip": source_ip,
        "process_name": process_name,
        "raw_payload": details or {},
        "normalized_payload": {
            "source": "cyberguard_collector",
            "host": socket.gethostname(),
            "details": details or {}
        },
        "tags": [category, event_type]
    }
