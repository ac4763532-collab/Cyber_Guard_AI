"""
CyberGuard AI - IOC (Indicator of Compromise) Detection

Manages IOC matching against known threat intelligence.
Supports various IOC types: IP, domain, URL, hash, email.
"""

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field
import structlog


logger = structlog.get_logger(__name__)


class IOCType(str, Enum):
    """Types of Indicators of Compromise."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    FILENAME = "filename"
    REGISTRY = "registry"
    CVE = "cve"


class ThreatLevel(str, Enum):
    """Threat level for IOCs."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class IOC(BaseModel):
    """An Indicator of Compromise."""

    ioc_id: str = Field(default_factory=lambda: str(uuid4()))
    ioc_type: IOCType
    value: str
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    description: str = ""
    source: str = "internal"
    tags: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    active: bool = True


class IOCMatch(BaseModel):
    """Result of an IOC match."""

    match_id: str = Field(default_factory=lambda: str(uuid4()))
    ioc: IOC
    matched_value: str
    matched_field: str
    context: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IOCMatcher:
    """
    IOC Matcher for detecting known threat indicators.

    Maintains an in-memory database of IOCs and provides
    efficient matching against incoming data.
    """

    def __init__(self):
        self._iocs: dict[IOCType, dict[str, IOC]] = {t: {} for t in IOCType}
        self._initialize_demo_iocs()

    def _initialize_demo_iocs(self) -> None:
        """Initialize with demo IOCs for testing."""
        # Known malicious domains (demo data)
        demo_domains = [
            ("evil-phishing.com", ThreatLevel.CRITICAL, "Known phishing domain"),
            ("malware-download.net", ThreatLevel.CRITICAL, "Malware distribution"),
            ("fake-bank-login.xyz", ThreatLevel.HIGH, "Credential harvesting"),
            ("suspicious-redirect.top", ThreatLevel.MEDIUM, "Suspicious redirect"),
        ]
        for domain, level, desc in demo_domains:
            self.add_ioc(IOC(
                ioc_type=IOCType.DOMAIN,
                value=domain.lower(),
                threat_level=level,
                description=desc,
                source="demo_feed",
                tags=["demo", "phishing"],
            ))

        # Known malicious IPs (demo data - using reserved ranges)
        demo_ips = [
            ("10.0.0.66", ThreatLevel.HIGH, "Known C2 server"),
            ("192.168.100.200", ThreatLevel.MEDIUM, "Suspicious scanner"),
        ]
        for ip, level, desc in demo_ips:
            self.add_ioc(IOC(
                ioc_type=IOCType.IP,
                value=ip,
                threat_level=level,
                description=desc,
                source="demo_feed",
                tags=["demo"],
            ))

        # URL shorteners used in phishing
        shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl"]
        for shortener in shorteners:
            self.add_ioc(IOC(
                ioc_type=IOCType.DOMAIN,
                value=shortener.lower(),
                threat_level=ThreatLevel.LOW,
                description="URL shortener - verify destination",
                source="internal",
                tags=["shortener"],
            ))

        logger.info("Demo IOCs initialized", count=self.get_ioc_count())

    def add_ioc(self, ioc: IOC) -> None:
        """Add an IOC to the database."""
        normalized_value = ioc.value.lower().strip()
        self._iocs[ioc.ioc_type][normalized_value] = ioc

    def remove_ioc(self, ioc_type: IOCType, value: str) -> bool:
        """Remove an IOC."""
        normalized = value.lower().strip()
        if normalized in self._iocs[ioc_type]:
            del self._iocs[ioc_type][normalized]
            return True
        return False

    def get_ioc(self, ioc_type: IOCType, value: str) -> IOC | None:
        """Get an IOC by type and value."""
        normalized = value.lower().strip()
        return self._iocs[ioc_type].get(normalized)

    def get_ioc_count(self) -> int:
        """Get total IOC count."""
        return sum(len(iocs) for iocs in self._iocs.values())

    def match(self, data: dict[str, Any]) -> list[IOCMatch]:
        """
        Match data against all IOCs.

        Args:
            data: Dictionary containing fields to check

        Returns:
            List of IOC matches
        """
        matches = []

        # Extract potential IOCs from data
        extracted = self._extract_potential_iocs(data)

        # Match against database
        for ioc_type, values in extracted.items():
            for value, field in values:
                ioc = self.get_ioc(ioc_type, value)
                if ioc and ioc.active:
                    # Update last_seen
                    ioc.last_seen = datetime.now(timezone.utc)

                    matches.append(IOCMatch(
                        ioc=ioc,
                        matched_value=value,
                        matched_field=field,
                        context=f"Found {ioc_type.value} IOC in field '{field}'",
                    ))

        return matches

    def _extract_potential_iocs(self, data: dict[str, Any]) -> dict[IOCType, list[tuple[str, str]]]:
        """Extract potential IOCs from data fields."""
        extracted: dict[IOCType, list[tuple[str, str]]] = {t: [] for t in IOCType}

        # IP pattern
        ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

        # Domain pattern (simplified)
        domain_pattern = re.compile(r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b')

        # Email pattern
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

        # Hash patterns
        md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
        sha1_pattern = re.compile(r'\b[a-fA-F0-9]{40}\b')
        sha256_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')

        def extract_from_value(value: Any, field: str) -> None:
            if not isinstance(value, str):
                value = str(value)

            # Extract IPs
            for match in ip_pattern.finditer(value):
                extracted[IOCType.IP].append((match.group(1), field))

            # Extract domains
            for match in domain_pattern.finditer(value):
                domain = match.group(0).lower()
                # Filter out common false positives
                if not domain.endswith(('.png', '.jpg', '.gif', '.css', '.js')):
                    extracted[IOCType.DOMAIN].append((domain, field))

            # Extract emails
            for match in email_pattern.finditer(value):
                extracted[IOCType.EMAIL].append((match.group(0).lower(), field))

            # Extract hashes
            for match in sha256_pattern.finditer(value):
                extracted[IOCType.SHA256].append((match.group(0).lower(), field))
            for match in sha1_pattern.finditer(value):
                if len(match.group(0)) == 40:  # Exact length
                    extracted[IOCType.SHA1].append((match.group(0).lower(), field))
            for match in md5_pattern.finditer(value):
                if len(match.group(0)) == 32:  # Exact length
                    extracted[IOCType.MD5].append((match.group(0).lower(), field))

        # Process all fields
        for field, value in data.items():
            if isinstance(value, str):
                extract_from_value(value, field)
            elif isinstance(value, list):
                for item in value:
                    extract_from_value(item, field)
            elif isinstance(value, dict):
                for k, v in value.items():
                    extract_from_value(v, f"{field}.{k}")

        return extracted

    def get_statistics(self) -> dict[str, Any]:
        """Get IOC statistics."""
        stats = {
            "total": self.get_ioc_count(),
            "by_type": {},
            "by_threat_level": {},
        }

        for ioc_type, iocs in self._iocs.items():
            if iocs:
                stats["by_type"][ioc_type.value] = len(iocs)
                for ioc in iocs.values():
                    level = ioc.threat_level.value
                    stats["by_threat_level"][level] = stats["by_threat_level"].get(level, 0) + 1

        return stats


# Singleton instance
_matcher: IOCMatcher | None = None


def get_ioc_matcher() -> IOCMatcher:
    """Get the global IOC matcher."""
    global _matcher
    if _matcher is None:
        _matcher = IOCMatcher()
    return _matcher
