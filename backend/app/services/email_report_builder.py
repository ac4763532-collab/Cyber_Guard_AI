"""
CyberGuard AI - Email Investigation Report Builder

Converts raw analysis results into professional SOC-style investigation reports.
"""

import re
from datetime import datetime, timezone
from typing import Any, Optional

from app.agents.base import AgentResult, Finding, Severity
from app.schemas.email_report import (
    EmailInvestigationReport,
    VerdictSection,
    SenderIntelligence,
    AuthenticationSection,
    AuthenticationResult,
    AuthStatus,
    URLIntelligence,
    ExtractedURL,
    ContentAnalysisSection,
    ContentAnalysisMatch,
    AttachmentSection,
    AttachmentAnalysis,
    HeaderForensics,
    IOCInventory,
    IOCEntry,
    IOCType,
    ThreatIntelSection,
    ThreatIntelResult,
    FindingDetail,
    RiskBreakdown,
    RecommendationItem,
    DetectionStatus,
    RiskLevel,
    get_risk_level,
)


class EmailReportBuilder:
    """
    Builds professional investigation reports from analysis results.

    Transforms raw EmailAgent output into structured, SOC-friendly reports
    with clear sections, evidence, and actionable recommendations.
    """

    def __init__(self):
        pass

    def build_report(
        self,
        agent_result: AgentResult,
        parsed_email: Optional[dict[str, Any]] = None,
        authentication: Optional[dict[str, Any]] = None,
        threat_intel: Optional[dict[str, Any]] = None,
        email_source: str = "manual",
        gmail_message_id: Optional[str] = None,
    ) -> EmailInvestigationReport:
        """
        Build complete investigation report.

        Args:
            agent_result: Result from EmailAgent analysis
            parsed_email: Parsed email data (from Gmail or manual)
            authentication: Authentication results (SPF/DKIM/DMARC)
            threat_intel: Threat intelligence results
            email_source: "manual" or "gmail"
            gmail_message_id: Gmail message ID if applicable

        Returns:
            EmailInvestigationReport with all sections populated
        """
        # Reuse the agent result's result_id rather than minting a separate
        # RPT-xxxx id: analysis_history is persisted keyed on result_id
        # (see app/api/v1/analysis.py:_persist_email_analysis_history), and
        # the feedback flow (POST /feedback) looks up analysis_id against
        # that table. A disconnected report_id would make every feedback
        # submission from the investigation report UI fail with "Analysis
        # not found" even though the row exists under a different id.
        report_id = agent_result.result_id

        # Build each section
        verdict = self._build_verdict(agent_result)
        sender = self._build_sender_section(agent_result, parsed_email)
        auth_section = self._build_authentication_section(authentication, parsed_email)
        urls = self._build_url_section(agent_result, parsed_email)
        content = self._build_content_section(agent_result)
        attachments = self._build_attachment_section(agent_result, parsed_email)
        headers = self._build_header_section(agent_result, parsed_email)
        iocs = self._build_ioc_inventory(agent_result, parsed_email)
        threat_intel_section = self._build_threat_intel_section(threat_intel)
        risk_breakdown = self._build_risk_breakdown(agent_result)
        all_findings = self._build_findings_list(agent_result)
        key_findings = all_findings[:5] if all_findings else []
        recommendations = self._build_recommendations(agent_result, verdict)
        executive_summary = self._build_executive_summary(agent_result, verdict, all_findings)
        detection_status = self._build_detection_status(
            sender, auth_section, urls, content, attachments, headers, threat_intel_section
        )

        return EmailInvestigationReport(
            report_id=report_id,
            investigation_timestamp=datetime.now(timezone.utc),
            analysis_duration_ms=agent_result.processing_time_ms or 0.0,
            agent_version=agent_result.agent_version,
            email_source=email_source,
            gmail_message_id=gmail_message_id,
            verdict=verdict,
            executive_summary=executive_summary,
            key_findings=key_findings,
            sender=sender,
            authentication=auth_section,
            urls=urls,
            content=content,
            attachments=attachments,
            headers=headers,
            threat_intel=threat_intel_section,
            iocs=iocs,
            risk_breakdown=risk_breakdown,
            all_findings=all_findings,
            recommendations=recommendations,
            detection_status=detection_status,
            raw_email_metadata=parsed_email,
        )

    def _build_verdict(self, result: AgentResult) -> VerdictSection:
        """Build verdict section from analysis result."""
        confidence_reasons = []

        # Build confidence reasons based on findings
        finding_count = len(result.findings)
        if finding_count >= 4:
            confidence_reasons.append(f"{finding_count} independent indicators detected")

        severity_counts = {}
        for f in result.findings:
            sev = f.severity.value if isinstance(f.severity, Severity) else f.severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        if severity_counts.get("critical", 0) > 0:
            confidence_reasons.append(f"{severity_counts['critical']} critical finding(s)")
        if severity_counts.get("high", 0) > 0:
            confidence_reasons.append(f"{severity_counts['high']} high severity finding(s)")

        # Add specific indicator types
        indicator_types = set()
        for f in result.findings:
            if "URL" in f.name or "url" in f.rule_id.lower() if f.rule_id else False:
                indicator_types.add("URL analysis")
            if "sender" in f.name.lower() or "domain" in f.name.lower():
                indicator_types.add("sender analysis")
            if "credential" in f.name.lower() or "urgency" in f.name.lower():
                indicator_types.add("content analysis")
            if "attach" in f.name.lower():
                indicator_types.add("attachment analysis")
            if "auth" in f.name.lower() or "spf" in f.name.lower() or "dkim" in f.name.lower():
                indicator_types.add("authentication analysis")

        for it in indicator_types:
            confidence_reasons.append(it)

        if not confidence_reasons:
            confidence_reasons.append("No significant threats detected")

        return VerdictSection(
            classification=result.classification,
            risk_score=result.risk_score,
            risk_level=get_risk_level(result.risk_score),
            severity=result.severity.value if isinstance(result.severity, Severity) else result.severity,
            confidence=result.confidence,
            confidence_reasons=confidence_reasons[:5],
        )

    def _build_sender_section(
        self,
        result: AgentResult,
        parsed_email: Optional[dict[str, Any]]
    ) -> SenderIntelligence:
        """Build sender intelligence section."""
        sender = SenderIntelligence()

        if parsed_email:
            sender.from_address = parsed_email.get("sender", "")
            sender.from_display_name = parsed_email.get("sender_name", "")
            sender.from_domain = self._extract_domain_from_email(parsed_email.get("sender_email", ""))
            sender.reply_to = parsed_email.get("reply_to", "")
            sender.reply_to_domain = self._extract_domain_from_email(parsed_email.get("reply_to_email", ""))
            sender.return_path = parsed_email.get("return_path", "")
            sender.return_path_domain = self._extract_domain_from_email(parsed_email.get("return_path_email", ""))

        # Check findings for sender-related issues
        findings = []
        for f in result.findings:
            rule_id = f.rule_id or ""
            name_lower = f.name.lower()

            if rule_id.startswith("EMAIL-") or "sender" in name_lower or "domain" in name_lower:
                findings.append({
                    "rule_id": f.rule_id,
                    "name": f.name,
                    "severity": f.severity.value if isinstance(f.severity, Severity) else f.severity,
                    "evidence": f.evidence,
                })

                if "free email" in name_lower:
                    sender.is_free_email_provider = True
                if "suspicious" in name_lower and "tld" in name_lower:
                    sender.is_suspicious_tld = True
                if "spoof" in name_lower or "lookalike" in name_lower or "impersonat" in name_lower:
                    sender.is_lookalike_domain = True
                if "reply-to" in name_lower and "mismatch" in name_lower:
                    sender.reply_to_mismatch = True
                if "return-path" in name_lower and "mismatch" in name_lower:
                    sender.return_path_mismatch = True

        sender.findings = findings
        return sender

    def _build_authentication_section(
        self,
        authentication: Optional[dict[str, Any]],
        parsed_email: Optional[dict[str, Any]]
    ) -> AuthenticationSection:
        """Build authentication section."""
        section = AuthenticationSection()

        if not authentication and parsed_email:
            authentication = parsed_email.get("authentication", {})

        if not authentication:
            section.spf = AuthenticationResult(status=AuthStatus.NOT_AVAILABLE, reason="No authentication data available")
            section.dkim = AuthenticationResult(status=AuthStatus.NOT_AVAILABLE, reason="No authentication data available")
            section.dmarc = AuthenticationResult(status=AuthStatus.NOT_AVAILABLE, reason="No authentication data available")
            return section

        # Parse SPF
        spf_value = authentication.get("spf", "unknown")
        if isinstance(spf_value, dict):
            spf_status = spf_value.get("result", "unknown")
            spf_domain = spf_value.get("domain", "")
        else:
            spf_status = str(spf_value) if spf_value else "unknown"
            spf_domain = authentication.get("spf_domain", "")

        section.spf = AuthenticationResult(
            status=self._parse_auth_status(spf_status),
            domain=spf_domain,
            evidence=f"SPF result: {spf_status}" if spf_status != "unknown" else "",
        )

        # Parse DKIM
        dkim_value = authentication.get("dkim", "unknown")
        if isinstance(dkim_value, dict):
            dkim_status = dkim_value.get("result", "unknown")
            dkim_domain = dkim_value.get("domain", "")
        else:
            dkim_status = str(dkim_value) if dkim_value else "unknown"
            dkim_domain = authentication.get("dkim_domain", "")

        section.dkim = AuthenticationResult(
            status=self._parse_auth_status(dkim_status),
            domain=dkim_domain,
            evidence=f"DKIM result: {dkim_status}" if dkim_status != "unknown" else "",
        )

        # Parse DMARC
        dmarc_value = authentication.get("dmarc", "unknown")
        if isinstance(dmarc_value, dict):
            dmarc_status = dmarc_value.get("result", "unknown")
            dmarc_domain = dmarc_value.get("domain", "")
        else:
            dmarc_status = str(dmarc_value) if dmarc_value else "unknown"
            dmarc_domain = authentication.get("dmarc_domain", "")

        section.dmarc = AuthenticationResult(
            status=self._parse_auth_status(dmarc_status),
            domain=dmarc_domain,
            evidence=f"DMARC result: {dmarc_status}" if dmarc_status != "unknown" else "",
        )

        # Raw header
        section.raw_header = authentication.get("raw_results", "")

        return section

    def _parse_auth_status(self, status: str) -> AuthStatus:
        """Parse authentication status string to enum."""
        status_lower = status.lower().strip()
        mapping = {
            "pass": AuthStatus.PASS,
            "fail": AuthStatus.FAIL,
            "softfail": AuthStatus.SOFTFAIL,
            "neutral": AuthStatus.NEUTRAL,
            "none": AuthStatus.NONE,
            "temperror": AuthStatus.TEMPERROR,
            "permerror": AuthStatus.PERMERROR,
        }
        return mapping.get(status_lower, AuthStatus.UNKNOWN)

    def _build_url_section(
        self,
        result: AgentResult,
        parsed_email: Optional[dict[str, Any]]
    ) -> URLIntelligence:
        """Build URL intelligence section."""
        section = URLIntelligence()

        # Get URLs from parsed email
        urls_detailed = []
        if parsed_email:
            urls_detailed = parsed_email.get("urls_detailed", [])
            if not urls_detailed:
                # Fallback to basic URL list
                basic_urls = parsed_email.get("urls", [])
                if isinstance(basic_urls, list):
                    for url in basic_urls:
                        if isinstance(url, str):
                            urls_detailed.append({"url": url})
                        elif isinstance(url, dict):
                            urls_detailed.append(url)

        # Build URL entries
        extracted_urls = []
        suspicious_count = 0
        has_url_service_data = False

        for url_data in urls_detailed:
            if isinstance(url_data, dict):
                url = url_data.get("url", "")
                domain = url_data.get("domain", "")
            else:
                url = str(url_data)
                domain = ""

            if not url:
                continue

            # Parse domain if not provided
            if not domain:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    domain = parsed.netloc
                except Exception:
                    pass

            entry = ExtractedURL(
                url=url,
                domain=domain,
                scheme=url_data.get("scheme", "") if isinstance(url_data, dict) else "",
                display_text=url_data.get("display_text", "") if isinstance(url_data, dict) else "",
                is_shortener=url_data.get("is_shortened", False) if isinstance(url_data, dict) else False,
                is_ip_based=url_data.get("is_ip_based", False) if isinstance(url_data, dict) else False,
                is_suspicious_tld=url_data.get("is_suspicious", False) if isinstance(url_data, dict) else False,
            )

            # Check for findings related to this URL from the agent
            findings = []
            for f in result.findings:
                if url in str(f.evidence) or domain in str(f.evidence):
                    findings.append(f.name)
                    if f.severity.value in ["critical", "high"]:
                        entry.severity = f.severity.value

            # Incorporate URL analysis service results when present
            svc_status = ""
            svc_is_malicious = False
            if isinstance(url_data, dict) and "url_service_status" in url_data:
                has_url_service_data = True
                svc_status = url_data.get("url_service_status", "unknown")
                svc_is_malicious = bool(url_data.get("url_service_is_malicious", False))
                svc_risk_score = int(url_data.get("url_service_risk_score", 0))

                if svc_is_malicious or svc_status == "malicious":
                    entry.severity = "critical"
                    findings.append(f"URL service: {svc_status} (risk {svc_risk_score})")
                elif svc_status == "suspicious":
                    if not entry.severity:
                        entry.severity = "medium"
                    findings.append(f"URL service: {svc_status} (risk {svc_risk_score})")

                # Surface individual pattern flags from the service
                svc_patterns = url_data.get("url_service_patterns", {})
                if svc_patterns.get("has_brand_in_subdomain"):
                    findings.append("URL service: brand in subdomain")
                if svc_patterns.get("has_homograph"):
                    findings.append("URL service: homograph domain")
                if svc_patterns.get("has_excessive_subdomains"):
                    findings.append("URL service: excessive subdomains")

            entry.findings = findings

            if (
                entry.is_shortener
                or entry.is_ip_based
                or entry.is_suspicious_tld
                or findings
                or svc_is_malicious
                or svc_status in ("malicious", "suspicious")
            ):
                suspicious_count += 1

            extracted_urls.append(entry)

        section.total_urls = len(extracted_urls)
        section.suspicious_urls = suspicious_count
        section.urls = extracted_urls
        # DETECTED: threats found; NOT_DETECTED: analysis ran, clean; UNKNOWN: URLs present
        # but no dedicated URL analysis was executed; NOT_APPLICABLE: no URLs at all.
        section.status = (
            DetectionStatus.DETECTED if suspicious_count > 0
            else DetectionStatus.NOT_DETECTED if has_url_service_data and len(extracted_urls) > 0
            else DetectionStatus.UNKNOWN if len(extracted_urls) > 0
            else DetectionStatus.NOT_APPLICABLE
        )

        return section

    def _build_content_section(self, result: AgentResult) -> ContentAnalysisSection:
        """Build content analysis section."""
        section = ContentAnalysisSection()

        for f in result.findings:
            name_lower = f.name.lower()
            rule_id = f.rule_id or ""

            if "urgency" in name_lower or rule_id == "CONTENT-001":
                section.urgency_detected = True
                section.urgency_matches.extend(f.evidence[:3])
                section.matches.append(ContentAnalysisMatch(
                    pattern_type="urgency",
                    matched_text="; ".join(f.evidence[:2]),
                    severity=f.severity.value if isinstance(f.severity, Severity) else f.severity,
                ))

            if "credential" in name_lower or rule_id == "CONTENT-002":
                section.credential_request_detected = True
                section.credential_matches.extend(f.evidence[:3])
                section.matches.append(ContentAnalysisMatch(
                    pattern_type="credential_request",
                    matched_text="; ".join(f.evidence[:2]),
                    severity=f.severity.value if isinstance(f.severity, Severity) else f.severity,
                ))

            if "brand" in name_lower or "impersonat" in name_lower or rule_id == "BRAND-001":
                section.brand_impersonation_detected = True
                # Extract brand name from evidence
                for ev in f.evidence:
                    if "brand" in ev.lower():
                        match = re.search(r'brand.*?:\s*(\w+)', ev, re.I)
                        if match:
                            section.impersonated_brands.append(match.group(1))
                section.matches.append(ContentAnalysisMatch(
                    pattern_type="brand_impersonation",
                    matched_text="; ".join(f.evidence[:2]),
                    severity=f.severity.value if isinstance(f.severity, Severity) else f.severity,
                ))

        # Calculate social engineering score
        se_score = 0
        if section.urgency_detected:
            se_score += 30
        if section.credential_request_detected:
            se_score += 40
        if section.brand_impersonation_detected:
            se_score += 30
        section.social_engineering_score = min(se_score, 100)

        return section

    def _build_attachment_section(
        self,
        result: AgentResult,
        parsed_email: Optional[dict[str, Any]]
    ) -> AttachmentSection:
        """Build attachment analysis section."""
        section = AttachmentSection()

        attachments_data = []
        if parsed_email:
            attachments_data = parsed_email.get("attachments", [])

        if not attachments_data:
            section.status = DetectionStatus.NOT_APPLICABLE
            return section

        dangerous_count = 0
        attachment_entries = []

        for att in attachments_data:
            if isinstance(att, dict):
                filename = att.get("filename", "unknown")
                mime_type = att.get("mime_type", "")
                size = att.get("size", 0)
                sha256 = att.get("sha256", "")
            else:
                filename = str(att)
                mime_type = ""
                size = 0
                sha256 = ""

            # Get extension
            extension = ""
            if "." in filename:
                extension = "." + filename.rsplit(".", 1)[-1].lower()

            entry = AttachmentAnalysis(
                filename=filename,
                extension=extension,
                mime_type=mime_type,
                size=size,
                sha256=sha256,
            )

            # Check findings for this attachment
            findings = []
            for f in result.findings:
                if filename.lower() in str(f.evidence).lower():
                    findings.append(f.name)

                    name_lower = f.name.lower()
                    if "dangerous" in name_lower:
                        entry.is_dangerous_extension = True
                    if "double" in name_lower:
                        entry.is_double_extension = True
                    if "macro" in name_lower:
                        entry.is_macro_enabled = True
                    if "archive" in name_lower:
                        entry.is_archive = True
                    if "disk image" in name_lower:
                        entry.is_disk_image = True
                    if "mime" in name_lower and "mismatch" in name_lower:
                        entry.has_mime_mismatch = True

                    if f.severity.value in ["critical", "high"]:
                        entry.severity = f.severity.value

            entry.findings = findings

            if entry.is_dangerous_extension or entry.is_double_extension or entry.is_macro_enabled:
                dangerous_count += 1

            attachment_entries.append(entry)

        section.total_attachments = len(attachment_entries)
        section.dangerous_attachments = dangerous_count
        section.attachments = attachment_entries
        section.status = (
            DetectionStatus.DETECTED if dangerous_count > 0
            else DetectionStatus.NOT_DETECTED
        )

        return section

    def _build_header_section(
        self,
        result: AgentResult,
        parsed_email: Optional[dict[str, Any]]
    ) -> HeaderForensics:
        """Build header forensics section."""
        section = HeaderForensics()

        if parsed_email:
            section.message_id = parsed_email.get("message_id", "")
            section.received_chain = parsed_email.get("received_chain", [])
            section.received_hops = len(section.received_chain)

        section.message_id_present = bool(section.message_id)

        # Check findings for header issues
        findings = []
        for f in result.findings:
            rule_id = f.rule_id or ""
            name_lower = f.name.lower()

            if rule_id.startswith("HEADER-") or "header" in name_lower or "hop" in name_lower:
                findings.append({
                    "rule_id": f.rule_id,
                    "name": f.name,
                    "severity": f.severity.value if isinstance(f.severity, Severity) else f.severity,
                    "evidence": f.evidence,
                })

                if "excessive" in name_lower or "hop" in name_lower:
                    section.excessive_hops = True
                if "private" in name_lower or "localhost" in name_lower:
                    section.has_private_ip = True
                    section.has_localhost = "localhost" in name_lower
                if "timestamp" in name_lower:
                    section.has_timestamp_anomaly = True
                if "message-id" in name_lower and "missing" in name_lower:
                    section.message_id_present = False
                if "return-path" in name_lower and "mismatch" in name_lower:
                    section.return_path_from_mismatch = True

        section.findings = findings
        section.status = (
            DetectionStatus.DETECTED if findings
            else DetectionStatus.NOT_DETECTED if section.message_id
            else DetectionStatus.UNKNOWN
        )

        return section

    def _build_ioc_inventory(
        self,
        result: AgentResult,
        parsed_email: Optional[dict[str, Any]]
    ) -> IOCInventory:
        """Build IOC inventory section."""
        inventory = IOCInventory()

        domains = set()
        ips = set()
        urls = set()
        hashes = set()
        emails = set()
        iocs = []

        # From agent result indicators
        for indicator in result.indicators:
            indicator_str = str(indicator)

            # Classify IOC type
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', indicator_str):
                ips.add(indicator_str)
                iocs.append(IOCEntry(ioc_type=IOCType.IP, value=indicator_str, source="email_agent"))
            elif re.match(r'^https?://', indicator_str):
                urls.add(indicator_str)
                iocs.append(IOCEntry(ioc_type=IOCType.URL, value=indicator_str, source="email_agent"))
            elif re.match(r'^[a-fA-F0-9]{64}$', indicator_str):
                hashes.add(indicator_str)
                iocs.append(IOCEntry(ioc_type=IOCType.HASH_SHA256, value=indicator_str, source="email_agent"))
            elif re.match(r'^[a-fA-F0-9]{40}$', indicator_str):
                hashes.add(indicator_str)
                iocs.append(IOCEntry(ioc_type=IOCType.HASH_SHA1, value=indicator_str, source="email_agent"))
            elif re.match(r'^[a-fA-F0-9]{32}$', indicator_str):
                hashes.add(indicator_str)
                iocs.append(IOCEntry(ioc_type=IOCType.HASH_MD5, value=indicator_str, source="email_agent"))
            elif '@' in indicator_str:
                emails.add(indicator_str)
                iocs.append(IOCEntry(ioc_type=IOCType.EMAIL, value=indicator_str, source="email_agent"))
            else:
                # Assume domain
                domains.add(indicator_str)
                iocs.append(IOCEntry(ioc_type=IOCType.DOMAIN, value=indicator_str, source="email_agent"))

        # Add URLs from parsed email
        if parsed_email:
            for url_data in parsed_email.get("urls_detailed", []):
                url = url_data.get("url", "") if isinstance(url_data, dict) else str(url_data)
                if url and url not in urls:
                    urls.add(url)
                    iocs.append(IOCEntry(ioc_type=IOCType.URL, value=url, source="email_parser"))

                domain = url_data.get("domain", "") if isinstance(url_data, dict) else ""
                if domain and domain not in domains:
                    domains.add(domain)
                    iocs.append(IOCEntry(ioc_type=IOCType.DOMAIN, value=domain, source="email_parser"))

        inventory.total_iocs = len(iocs)
        inventory.iocs = iocs
        inventory.domains = list(domains)
        inventory.ips = list(ips)
        inventory.urls = list(urls)
        inventory.hashes = list(hashes)
        inventory.emails = list(emails)

        return inventory

    def _build_threat_intel_section(
        self,
        threat_intel: Optional[dict[str, Any]]
    ) -> ThreatIntelSection:
        """Build threat intelligence section."""
        from app.services.threat_intel import get_threat_intel_service

        section = ThreatIntelSection()

        # Check if threat intel service is actually configured
        ti_service = get_threat_intel_service()
        if not ti_service.is_configured:
            section.status = "not_configured"
            return section

        # Service is configured
        section.status = "configured"

        # If no results passed, it means no IOCs were extracted or all were trusted
        if not threat_intel:
            # Service is configured but no IOCs to look up
            section.status = "no_iocs"  # New status: configured but no suspicious IOCs
            return section

        results = []
        for ioc, data in threat_intel.items():
            if isinstance(data, dict):
                # ThreatIntelService may now report risk_score/is_malicious as
                # None (lookup failed or was inconclusive, never fabricated as
                # 0/clean - see threat_intel/service.py's ReputationStatus
                # policy). This section's own schema still treats risk_score
                # as always-numeric, so normalize None -> 0 here rather than
                # at the service layer: `.get("risk_score", 0)` only applies
                # the default when the key is *absent*, not when its value is
                # explicitly None, so a bare None would otherwise reach the
                # `> 30` comparisons below and raise a TypeError.
                is_malicious = data.get("is_malicious")
                risk_score = data.get("risk_score")
                if risk_score is None:
                    risk_score = 0

                result = ThreatIntelResult(
                    ioc=ioc,
                    ioc_type=data.get("type", "unknown"),
                    provider=", ".join(data.get("sources", ["unknown"])),
                    status="malicious" if is_malicious else "suspicious" if risk_score > 30 else "clean",
                    risk_score=risk_score,
                    details=data,
                )
                results.append(result)

                if is_malicious:
                    section.malicious_count += 1
                elif risk_score > 30:
                    section.suspicious_count += 1

        section.results = results

        # Extract providers
        providers = set()
        for r in results:
            for p in r.provider.split(", "):
                providers.add(p)
        section.providers_available = list(providers)

        return section

    def _build_risk_breakdown(self, result: AgentResult) -> RiskBreakdown:
        """Build risk score breakdown."""
        breakdown = RiskBreakdown(total_score=result.risk_score)

        for f in result.findings:
            sev = f.severity.value if isinstance(f.severity, Severity) else f.severity
            rule_id = f.rule_id or ""

            # Count by severity
            if sev == "critical":
                breakdown.critical_findings += 1
            elif sev == "high":
                breakdown.high_findings += 1
            elif sev == "medium":
                breakdown.medium_findings += 1
            elif sev == "low":
                breakdown.low_findings += 1
            else:
                breakdown.info_findings += 1

            # Estimate component scores based on rule categories
            # This is an approximation - actual implementation should track this during analysis
            if rule_id.startswith("EMAIL-"):
                breakdown.sender_score += 15 if sev in ["critical", "high"] else 5
            elif rule_id.startswith("AUTH-"):
                breakdown.authentication_score += 20 if sev in ["critical", "high"] else 10
            elif rule_id.startswith("URL-"):
                breakdown.url_score += 15 if sev in ["critical", "high"] else 5
            elif rule_id.startswith("CONTENT-"):
                breakdown.content_score += 15 if sev in ["critical", "high"] else 5
            elif rule_id.startswith("ATTACH-"):
                breakdown.attachment_score += 20 if sev in ["critical", "high"] else 10
            elif rule_id.startswith("HEADER-"):
                breakdown.header_score += 10 if sev in ["critical", "high"] else 5

        return breakdown

    def _build_findings_list(self, result: AgentResult) -> list[FindingDetail]:
        """Build detailed findings list."""
        findings = []

        for f in result.findings:
            sev = f.severity.value if isinstance(f.severity, Severity) else f.severity

            # Determine risk contribution
            risk_contrib = 30 if sev == "critical" else 15 if sev == "high" else 5 if sev == "medium" else 2

            # Determine source from rule_id
            rule_id = f.rule_id or ""
            if rule_id.startswith("EMAIL-"):
                source = "Sender Analyzer"
            elif rule_id.startswith("AUTH-"):
                source = "Authentication Analyzer"
            elif rule_id.startswith("URL-"):
                source = "URL Analyzer"
            elif rule_id.startswith("CONTENT-"):
                source = "Content Analyzer"
            elif rule_id.startswith("ATTACH-"):
                source = "Attachment Analyzer"
            elif rule_id.startswith("HEADER-"):
                source = "Header Analyzer"
            elif rule_id.startswith("BRAND-"):
                source = "Brand Impersonation Detector"
            else:
                source = "Email Security Agent"

            # Generate "why it matters"
            why = self._get_why_it_matters(f.name, sev)

            findings.append(FindingDetail(
                finding_id=f.finding_id,
                rule_id=f.rule_id,
                title=f.name,
                severity=sev,
                description=f.description,
                evidence=f.evidence,
                source=source,
                risk_contribution=risk_contrib,
                why_it_matters=why,
                mitre_techniques=f.mitre_techniques,
                recommendations=f.recommendations,
            ))

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda x: severity_order.get(x.severity, 5))

        return findings

    def _get_why_it_matters(self, finding_name: str, severity: str) -> str:
        """Generate explanation for why a finding matters."""
        name_lower = finding_name.lower()

        explanations = {
            "credential": "Credential requests in emails are a primary phishing technique used to steal login information.",
            "urgency": "Urgency tactics pressure users into acting without thinking, a key social engineering technique.",
            "shortener": "URL shorteners hide the true destination, commonly used to obscure malicious links.",
            "ip-based": "IP-based URLs bypass domain reputation checks and are rarely used by legitimate services.",
            "mismatch": "Mismatched headers indicate the email may not be from who it claims to be.",
            "spf": "SPF failures mean the sending server is not authorized to send for this domain.",
            "dkim": "DKIM failures indicate the email content may have been tampered with.",
            "dmarc": "DMARC failures are strong indicators of email spoofing or phishing.",
            "dangerous": "Dangerous file types can contain executable code that may compromise your system.",
            "macro": "Macro-enabled documents are a common malware delivery mechanism.",
            "double": "Double extensions are a technique to disguise executable files as documents.",
            "brand": "Brand impersonation tricks users into trusting malicious content.",
            "free email": "Legitimate organizations rarely send official communications from free email providers.",
        }

        for key, explanation in explanations.items():
            if key in name_lower:
                return explanation

        return f"This {severity} severity finding indicates a potential security issue that requires attention."

    def _build_recommendations(
        self,
        result: AgentResult,
        verdict: VerdictSection
    ) -> list[RecommendationItem]:
        """Build actionable recommendations."""
        recommendations = []

        # Add recommendations from findings
        seen_actions = set()

        for f in result.findings:
            for rec in f.recommendations:
                if rec not in seen_actions:
                    seen_actions.add(rec)
                    sev = f.severity.value if isinstance(f.severity, Severity) else f.severity
                    priority = "immediate" if sev in ["critical", "high"] else "medium" if sev == "medium" else "low"

                    recommendations.append(RecommendationItem(
                        action=rec,
                        priority=priority,
                        based_on=f.name,
                    ))

        # Add verdict-based recommendations
        if verdict.classification in ["phishing", "malicious"]:
            if "Do not click any links" not in seen_actions:
                recommendations.insert(0, RecommendationItem(
                    action="Do not click any links in this email",
                    priority="immediate",
                    based_on=f"Classification: {verdict.classification}",
                ))
            if "Report to security team" not in seen_actions:
                recommendations.insert(1, RecommendationItem(
                    action="Report this email to your security team",
                    priority="immediate",
                    based_on=f"Classification: {verdict.classification}",
                ))
            if "Delete the email" not in seen_actions:
                recommendations.append(RecommendationItem(
                    action="Delete this email from your inbox",
                    priority="high",
                    based_on=f"Classification: {verdict.classification}",
                ))

        return recommendations[:10]  # Limit to 10 recommendations

    def _build_executive_summary(
        self,
        result: AgentResult,
        verdict: VerdictSection,
        findings: list[FindingDetail]
    ) -> str:
        """Build executive summary."""
        if verdict.classification == "benign":
            return "No significant security threats were detected in this email. The email appears to be legitimate."

        finding_names = [f.title for f in findings[:3]]
        finding_summary = ", ".join(finding_names)
        if len(findings) > 3:
            finding_summary += f" and {len(findings) - 3} more"

        risk_desc = {
            "critical": "This email poses an IMMEDIATE threat",
            "high": "This email shows strong indicators of malicious intent",
            "medium": "This email contains suspicious indicators",
            "low": "This email has minor suspicious characteristics",
        }

        risk_text = risk_desc.get(verdict.risk_level.value, "This email requires review")

        return (
            f"{risk_text}. "
            f"Classification: {verdict.classification.upper()} with {int(verdict.confidence * 100)}% confidence. "
            f"Detected {len(findings)} security indicator(s): {finding_summary}. "
            f"Risk score: {verdict.risk_score}/100."
        )

    def _build_detection_status(
        self,
        sender: SenderIntelligence,
        auth: AuthenticationSection,
        urls: URLIntelligence,
        content: ContentAnalysisSection,
        attachments: AttachmentSection,
        headers: HeaderForensics,
        threat_intel: ThreatIntelSection,
    ) -> dict[str, str]:
        """Build detection status summary."""
        return {
            "sender_analysis": "DETECTED" if sender.findings else "NOT_DETECTED",
            "spf": auth.spf.status.value.upper(),
            "dkim": auth.dkim.status.value.upper(),
            "dmarc": auth.dmarc.status.value.upper(),
            "url_analysis": urls.status.value.upper(),
            "content_analysis": "DETECTED" if content.matches else "NOT_DETECTED",
            "attachment_analysis": attachments.status.value.upper(),
            "header_analysis": headers.status.value.upper(),
            "threat_intelligence": threat_intel.status.upper(),
        }

    def _extract_domain_from_email(self, email: str) -> str:
        """Extract domain from email address."""
        if not email or "@" not in email:
            return ""
        return email.split("@")[-1].lower()


# Singleton
_report_builder: Optional[EmailReportBuilder] = None


def get_report_builder() -> EmailReportBuilder:
    """Get the global report builder instance."""
    global _report_builder
    if _report_builder is None:
        _report_builder = EmailReportBuilder()
    return _report_builder
