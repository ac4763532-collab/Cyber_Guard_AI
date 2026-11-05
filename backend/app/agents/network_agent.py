"""
CyberGuard AI - Network Analysis Agent

Specialized agent for authorized network security assessments.

⚠️ IMPORTANT: This agent should ONLY be used to scan systems
   you own or have explicit authorization to assess.

Capabilities:
1. Host discovery
2. Port scanning (common ports)
3. Service detection
4. Version identification
5. Vulnerability enrichment (basic CVE lookup)
6. Risk assessment

Scan Types:
- basic: Host discovery + common ports
- service: Service and version detection
- full: Comprehensive scan

This agent uses Nmap for scanning. If Nmap is not installed,
it will simulate results for demonstration purposes.
"""

import re
import asyncio
import shutil
import xml.etree.ElementTree as ET
from typing import Any
from datetime import datetime

from app.schemas.analysis import validate_scan_target_address

from app.agents.base import (
    BaseAgent,
    AgentType,
    AgentStatus,
    AgentResult,
    Finding,
    Severity,
)


# =============================================================================
# Known Vulnerable Services (for demo enrichment)
# =============================================================================

# Common services with known vulnerabilities (simplified for demo)
KNOWN_VULNERABLE_VERSIONS = {
    "openssh": {
        "7.": ["CVE-2020-15778", "CVE-2019-6111"],
        "6.": ["CVE-2016-10012", "CVE-2016-10009"],
    },
    "apache": {
        "2.4.49": ["CVE-2021-41773"],
        "2.4.50": ["CVE-2021-42013"],
        "2.2.": ["CVE-2017-3167", "CVE-2017-3169"],
    },
    "nginx": {
        "1.16.": ["CVE-2019-20372"],
        "1.14.": ["CVE-2019-20372"],
    },
    "mysql": {
        "5.7.": ["CVE-2020-14812", "CVE-2020-14765"],
        "5.6.": ["CVE-2019-2537", "CVE-2019-2481"],
    },
    "vsftpd": {
        "2.3.4": ["CVE-2011-2523"],  # Famous backdoor
    },
    "proftpd": {
        "1.3.5": ["CVE-2015-3306"],
    },
}

# High-risk ports
HIGH_RISK_PORTS = {
    21: ("FTP", "high", "FTP transmits credentials in plaintext"),
    23: ("Telnet", "critical", "Telnet is unencrypted, use SSH instead"),
    445: ("SMB", "high", "SMB is frequently targeted by ransomware"),
    3389: ("RDP", "high", "RDP is frequently targeted by attackers"),
    1433: ("MSSQL", "medium", "Database port exposed to network"),
    3306: ("MySQL", "medium", "Database port exposed to network"),
    5432: ("PostgreSQL", "medium", "Database port exposed to network"),
    6379: ("Redis", "high", "Redis often has no authentication"),
    27017: ("MongoDB", "high", "MongoDB often has no authentication"),
}

# Common ports to scan in basic mode
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]


# =============================================================================
# Network Analysis Agent
# =============================================================================

class NetworkAgent(BaseAgent):
    """
    Network Analysis Agent for authorized security assessments.
    """

    agent_type = AgentType.NETWORK
    agent_name = "Network Analysis Agent"
    agent_version = "0.1.0"

    def __init__(self):
        super().__init__()
        self._status = AgentStatus.ONLINE
        self._nmap_available = self._check_nmap()

    def _check_nmap(self) -> bool:
        """Check if nmap is available on the system."""
        return shutil.which("nmap") is not None

    async def validate(self, data: dict[str, Any]) -> tuple[bool, str | None]:
        """Validate network scan request."""
        target = data.get("target", "")
        authorized = data.get("authorized", False)

        if not target:
            return False, "Target IP or CIDR is required"

        # Validate IP/CIDR format
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$"
        if not re.match(ip_pattern, target):
            return False, "Invalid IP address or CIDR format"

        # Validate IP octets
        parts = target.split("/")[0].split(".")
        for part in parts:
            if int(part) > 255:
                return False, f"Invalid IP octet: {part}"

        # Validate CIDR if present
        if "/" in target:
            cidr = int(target.split("/")[1])
            if cidr < 24 or cidr > 32:
                return False, "CIDR must be between /24 and /32 for safety"

        # Reject loopback/link-local/cloud-metadata targets outright, even
        # with authorized=True. Defense in depth - the same check already
        # runs in NetworkAnalysisRequest.validate_target, but this agent
        # can also be invoked directly (e.g. by the dispatcher), so it must
        # not rely solely on the API schema layer having run first.
        rejection = validate_scan_target_address(target)
        if rejection:
            return False, rejection

        # Check authorization
        if not authorized:
            return False, "You must confirm authorization to scan this target"

        return True, None

    async def analyze_connection_event(self, data: dict[str, Any]) -> AgentResult:
        """
        Analyze a single observed connection tuple from the local network
        monitor collector (app/logs/collectors/local_network.py) - NOT a
        scan. This is a passive classification of one already-established
        connection (local_addr/port, remote_addr/port, protocol, pid,
        process_name), not an active probe of a target, so it does not
        use validate()/the nmap path and carries no "authorized" concept
        - there is nothing being scanned, only an existing connection being
        looked at.

        Reuses HIGH_RISK_PORTS (the same table analyze()'s scan path uses)
        so "this remote port is high-risk" means the same thing whether it
        was discovered by scanning or observed in a live connection.
        Intentionally conservative/minimal per plan scope: flags outbound
        connections to a HIGH_RISK_PORTS remote port, and separately flags
        a remote connection on a non-standard port with no resolvable
        process name (observed-but-unattributed egress) - it does not
        attempt deep protocol inspection, reputation lookups, or anything
        beyond what the two signals already available here support.
        """
        # This method is called directly by the event bus consumer
        # (app/event_bus/dispatcher_integration.py), bypassing
        # BaseAgent.run() entirely - validate() would reject this data
        # (it requires "target"/"authorized" for the scan path, which a
        # connection tuple doesn't have), and this input doesn't need
        # authorization validation anyway since nothing is being scanned.
        # Mirror run()'s own try/except-to-error-result behavior here
        # since there's no run() wrapper for this path to rely on.
        try:
            return self._analyze_connection_event_inner(data)
        except Exception as e:
            self._error_count += 1
            return self._create_error_result(f"Connection event analysis error: {str(e)}")

    def _analyze_connection_event_inner(self, data: dict[str, Any]) -> AgentResult:
        remote_addr = data.get("remote_addr")
        remote_port = data.get("remote_port")
        local_addr = data.get("local_addr")
        local_port = data.get("local_port")
        protocol = data.get("protocol", "tcp")
        process_name = data.get("process_name")
        pid = data.get("pid")

        findings: list[Finding] = []
        indicators: list[str] = []

        # Nothing to classify for a purely local/listening socket - no
        # remote endpoint means no external exposure to assess here.
        if remote_addr:
            indicators.append(remote_addr)

            if remote_port in HIGH_RISK_PORTS:
                risk_name, risk_level, risk_reason = HIGH_RISK_PORTS[remote_port]
                severity = Severity.CRITICAL if risk_level == "critical" else (
                    Severity.HIGH if risk_level == "high" else Severity.MEDIUM
                )
                findings.append(Finding(
                    rule_id="NET-CONN-001",
                    name=f"Connection to high-risk port: {remote_port}/{risk_name}",
                    description=risk_reason,
                    severity=severity,
                    confidence=0.8,
                    evidence=[
                        f"Local: {local_addr}:{local_port}",
                        f"Remote: {remote_addr}:{remote_port}",
                        f"Protocol: {protocol}",
                        f"Process: {process_name or 'unknown'}" + (f" (pid {pid})" if pid else ""),
                    ],
                    mitre_techniques=["T1071"],
                    recommendations=[
                        f"Verify this connection to port {remote_port} is expected",
                        "Review the originating process for legitimacy",
                        "Implement firewall rules to restrict outbound access if unexpected",
                    ],
                    source_ip=remote_addr,
                ))

            # Observed-but-unattributed egress: a remote connection whose
            # owning process couldn't be resolved (psutil denied/exited
            # before lookup) is worth a lower-confidence, lower-severity
            # note - it is common and often benign (short-lived process),
            # so this must not be reported with the same confidence as an
            # actual high-risk-port match above.
            elif process_name is None and pid is not None:
                findings.append(Finding(
                    rule_id="NET-CONN-002",
                    name="Outbound connection with unresolved process",
                    description=(
                        "A remote connection was observed but the owning "
                        "process could not be identified (exited or "
                        "access denied before lookup)."
                    ),
                    severity=Severity.LOW,
                    confidence=0.4,
                    evidence=[
                        f"Local: {local_addr}:{local_port}",
                        f"Remote: {remote_addr}:{remote_port}",
                        f"Protocol: {protocol}",
                        f"PID: {pid} (process name unresolved)",
                    ],
                    mitre_techniques=["T1071"],
                    recommendations=[
                        "Review process activity around this timestamp if this recurs",
                    ],
                    source_ip=remote_addr,
                ))

        if not findings:
            classification, severity, confidence, risk_score = "benign", Severity.INFO, 0.85, 5
            summary = (
                f"Connection observed: {local_addr}:{local_port} -> "
                f"{remote_addr}:{remote_port} ({protocol}). No risk indicators."
                if remote_addr else
                f"Local/listening socket observed: {local_addr}:{local_port} ({protocol})."
            )
        else:
            critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
            high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
            risk_score = min(100, critical_count * 30 + high_count * 15 + len(findings) * 8)
            if critical_count > 0:
                classification, severity, confidence = "malicious", Severity.CRITICAL, 0.8
            elif high_count > 0:
                classification, severity, confidence = "suspicious", Severity.HIGH, 0.8
            else:
                classification, severity, confidence = "suspicious", Severity.LOW, 0.6
            summary = (
                f"Connection {local_addr}:{local_port} -> {remote_addr}:{remote_port} "
                f"({protocol}) flagged {len(findings)} issue(s). Classification: {classification.upper()}."
            )

        recommendations: list[str] = []
        for finding in findings:
            for rec in finding.recommendations:
                if rec not in recommendations:
                    recommendations.append(rec)

        return self._create_result(
            classification=classification,
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            findings=findings,
            summary=summary,
            indicators=indicators,
            recommendations=recommendations,
            data_source="local_network_monitor",
        )

    async def analyze(self, data: dict[str, Any]) -> AgentResult:
        """Perform network security assessment."""
        target = data.get("target", "")
        scan_type = data.get("scan_type", "basic").lower()

        findings: list[Finding] = []
        indicators: list[str] = []

        # Perform scan (or simulate if nmap not available)
        if self._nmap_available:
            scan_results = await self._run_nmap_scan(target, scan_type)
        else:
            scan_results = self._simulate_scan(target, scan_type)

        # Analyze results
        for host in scan_results.get("hosts", []):
            host_ip = host.get("ip", target)
            indicators.append(host_ip)

            # Analyze open ports
            for port_info in host.get("ports", []):
                port = port_info.get("port")
                service = port_info.get("service", "unknown")
                version = port_info.get("version", "")
                state = port_info.get("state", "open")

                if state != "open":
                    continue

                # Check for high-risk ports
                if port in HIGH_RISK_PORTS:
                    risk_name, risk_level, risk_reason = HIGH_RISK_PORTS[port]
                    severity = Severity.CRITICAL if risk_level == "critical" else (
                        Severity.HIGH if risk_level == "high" else Severity.MEDIUM
                    )
                    findings.append(Finding(
                        rule_id="NET-001",
                        name=f"High-risk port open: {port}/{risk_name}",
                        description=f"{risk_reason}",
                        severity=severity,
                        confidence=0.95,
                        evidence=[
                            f"Host: {host_ip}",
                            f"Port: {port}",
                            f"Service: {service}",
                            f"Version: {version}" if version else "Version: unknown",
                        ],
                        mitre_techniques=["T1046"],
                        recommendations=[
                            f"Review if port {port} needs to be exposed",
                            "Implement firewall rules to restrict access",
                            "Use encrypted alternatives where possible",
                        ],
                    ))

                # Check for vulnerable versions
                if version:
                    cves = self._check_vulnerable_version(service, version)
                    if cves:
                        findings.append(Finding(
                            rule_id="NET-002",
                            name=f"Potentially vulnerable service: {service}",
                            description=f"Service version may be affected by known vulnerabilities",
                            severity=Severity.HIGH,
                            confidence=0.75,
                            evidence=[
                                f"Host: {host_ip}",
                                f"Service: {service}",
                                f"Version: {version}",
                                f"Potential CVEs: {', '.join(cves)}",
                            ],
                            mitre_techniques=["T1190"],
                            recommendations=[
                                f"Update {service} to the latest version",
                                "Review CVE details for exploitability",
                                "Apply security patches",
                            ],
                        ))

            # Check for excessive open ports
            open_ports = [p for p in host.get("ports", []) if p.get("state") == "open"]
            if len(open_ports) > 10:
                findings.append(Finding(
                    rule_id="NET-003",
                    name="Excessive open ports",
                    description=f"Host has {len(open_ports)} open ports which increases attack surface",
                    severity=Severity.MEDIUM,
                    confidence=0.8,
                    evidence=[
                        f"Host: {host_ip}",
                        f"Open ports: {len(open_ports)}",
                        f"Ports: {', '.join(str(p['port']) for p in open_ports[:10])}...",
                    ],
                    mitre_techniques=["T1046"],
                    recommendations=[
                        "Review and close unnecessary ports",
                        "Implement principle of least privilege for network services",
                    ],
                ))

        # Calculate risk
        classification, severity, confidence, risk_score = self._calculate_risk(findings, scan_results)

        # Generate recommendations
        recommendations = self._generate_recommendations(findings, scan_results)

        # Build summary
        summary = self._build_summary(classification, findings, scan_results, indicators)

        return self._create_result(
            classification=classification,
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            findings=findings,
            summary=summary,
            indicators=indicators,
            recommendations=recommendations,
            data_source=scan_results.get("data_source", "simulated" if scan_results.get("simulated") else "nmap"),
            scan_warnings=scan_results.get("warnings", []),
        )

    # -------------------------------------------------------------------------
    # Scanning Methods
    # -------------------------------------------------------------------------

    async def _run_nmap_scan(self, target: str, scan_type: str) -> dict:
        """Run actual nmap scan. Falls back to simulation only when nmap
        itself cannot produce a result - the fallback always sets
        data_source/warnings so callers never mistake simulated data for
        a real scan."""
        try:
            # Build nmap command based on scan type
            if scan_type == "basic":
                cmd = ["nmap", "-sT", "-p", ",".join(map(str, COMMON_PORTS)), "-oX", "-", target]
            elif scan_type == "service":
                cmd = ["nmap", "-sT", "-sV", "-p", ",".join(map(str, COMMON_PORTS)), "-oX", "-", target]
            else:  # full
                cmd = ["nmap", "-sT", "-sV", "-p-", "--top-ports", "100", "-oX", "-", target]

            # Run nmap with timeout
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

            if proc.returncode != 0:
                # nmap ran but failed (e.g. permissions, bad target) - fall
                # back to simulation, but say so.
                return self._simulate_scan(
                    target, scan_type,
                    reason=f"nmap exited with an error (code {proc.returncode}); results below are simulated, not a real scan",
                )

            # Parse real nmap XML output
            return self._parse_nmap_xml(stdout.decode())

        except asyncio.TimeoutError:
            return self._simulate_scan(
                target, scan_type,
                reason="nmap timed out after 120s; results below are simulated, not a real scan",
            )
        except Exception as e:
            return self._simulate_scan(
                target, scan_type,
                reason=f"nmap scan failed ({e}); results below are simulated, not a real scan",
            )

    def _parse_nmap_xml(self, xml_output: str) -> dict:
        """Parse real nmap XML output using xml.etree.ElementTree (replaces
        the earlier regex-based parser, which could silently mis-parse or
        drop ports on malformed/unusual XML)."""
        results: dict = {
            "hosts": [],
            "scan_time": datetime.now().isoformat(),
            "simulated": False,
            "data_source": "nmap",
        }

        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError as e:
            # Malformed XML from nmap itself - don't guess, report it as a
            # scan that produced no usable evidence rather than fabricating
            # host/port data via regex guesswork.
            results["warnings"] = [f"Could not parse nmap output ({e}); no hosts reported"]
            return results

        for host_el in root.findall("host"):
            address_el = host_el.find("address[@addrtype='ipv4']")
            ip = address_el.get("addr") if address_el is not None else "unknown"

            ports: list[dict] = []
            ports_el = host_el.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    service_el = port_el.find("service")
                    ports.append({
                        "port": int(port_el.get("portid")),
                        "protocol": port_el.get("protocol", "tcp"),
                        "state": state_el.get("state") if state_el is not None else "unknown",
                        "service": service_el.get("name", "unknown") if service_el is not None else "unknown",
                        "version": service_el.get("version", "") if service_el is not None else "",
                    })

            results["hosts"].append({"ip": ip, "ports": ports})

        return results

    def _simulate_scan(self, target: str, scan_type: str, reason: str = "nmap not installed") -> dict:
        """
        Simulate scan results when a real scan could not be performed.

        This data is fabricated for demonstration purposes only - it must
        never be presented to a user as if it came from a real scan.
        Every caller of this method must propagate data_source/warnings
        from the returned dict into the final AgentResult so the API
        response and UI can show an explicit "simulated, not real" notice.
        """
        base_ip = target.split("/")[0]

        # Simulated host with common services
        simulated_ports = [
            {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 7.9"},
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "Apache 2.4.41"},
            {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "version": ""},
        ]

        # Add some risky ports for demo purposes
        if scan_type in ("service", "full"):
            simulated_ports.extend([
                {"port": 3306, "protocol": "tcp", "state": "open", "service": "mysql", "version": "MySQL 5.7.32"},
                {"port": 6379, "protocol": "tcp", "state": "open", "service": "redis", "version": "Redis 5.0.7"},
            ])

        return {
            "hosts": [{"ip": base_ip, "ports": simulated_ports}],
            "scan_time": datetime.now().isoformat(),
            "simulated": True,
            "data_source": "simulated",
            "warnings": [reason],
        }

    # -------------------------------------------------------------------------
    # Helper Methods
    # -------------------------------------------------------------------------

    def _check_vulnerable_version(self, service: str, version: str) -> list[str]:
        """Check if service version has known vulnerabilities."""
        cves = []
        service_lower = service.lower()

        for known_service, versions in KNOWN_VULNERABLE_VERSIONS.items():
            if known_service in service_lower:
                for ver_prefix, ver_cves in versions.items():
                    if ver_prefix in version.lower():
                        cves.extend(ver_cves)

        return cves

    def _calculate_risk(self, findings: list[Finding], scan_results: dict) -> tuple[str, Severity, float, int]:
        """Calculate overall risk."""
        if not findings:
            return "benign", Severity.INFO, 0.9, 10

        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        medium_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)

        risk_score = min(100, (
            critical_count * 30 +
            high_count * 15 +
            medium_count * 8 +
            len(findings) * 3
        ))

        if critical_count > 0 or risk_score >= 75:
            return "vulnerable", Severity.CRITICAL, 0.9, risk_score
        elif high_count > 0 or risk_score >= 50:
            return "vulnerable", Severity.HIGH, 0.85, risk_score
        elif medium_count > 0 or risk_score >= 25:
            return "at_risk", Severity.MEDIUM, 0.75, risk_score
        else:
            return "at_risk", Severity.LOW, 0.7, risk_score

    def _generate_recommendations(self, findings: list[Finding], scan_results: dict) -> list[str]:
        """Generate recommendations."""
        recommendations = [
            "Regularly audit open ports and services",
            "Keep all services updated to latest versions",
            "Implement network segmentation",
        ]

        for finding in findings:
            for rec in finding.recommendations:
                if rec not in recommendations:
                    recommendations.append(rec)

        return recommendations[:10]

    def _build_summary(self, classification: str, findings: list[Finding], scan_results: dict, indicators: list[str]) -> str:
        """Build summary."""
        hosts = scan_results.get("hosts", [])
        total_ports = sum(len(h.get("ports", [])) for h in hosts)
        simulated = scan_results.get("simulated", False)

        sim_note = " (simulated - nmap not installed)" if simulated else ""

        if classification == "benign":
            return f"Scanned {len(hosts)} host(s), {total_ports} port(s){sim_note}. No significant vulnerabilities detected."

        return (
            f"Scanned {len(hosts)} host(s), {total_ports} port(s){sim_note}. "
            f"Classification: {classification.upper()}. "
            f"Detected {len(findings)} security issue(s). "
            f"Review findings for remediation steps."
        )
