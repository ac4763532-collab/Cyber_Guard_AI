"""
CyberGuard AI - LLM Client

Client for Claude API integration with cybersecurity-focused prompts.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field
import structlog

from app.config import get_settings


logger = structlog.get_logger(__name__)


class LLMResponse(BaseModel):
    """Response from LLM analysis."""

    response_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Response content
    content: str
    structured_data: dict[str, Any] | None = None

    # Metadata
    model: str
    tokens_used: int = 0
    processing_time_ms: float = 0.0

    # Status
    success: bool = True
    error: str | None = None


class LLMClient:
    """
    LLM Client for Claude API integration.

    Provides cybersecurity-focused analysis capabilities:
    - Threat interpretation
    - Attack narrative generation
    - Remediation recommendations
    - IOC enrichment
    - MITRE ATT&CK mapping
    """

    def __init__(self):
        self._settings = get_settings()
        self._client = None
        self._initialized = False

        # Check if API key is available
        if self._settings.anthropic_api_key:
            try:
                import anthropic
                self._client = anthropic.Anthropic(
                    api_key=self._settings.anthropic_api_key
                )
                self._initialized = True
                logger.info("LLM client initialized", model=self._settings.llm_model)
            except ImportError:
                logger.warning("anthropic package not installed")
            except Exception as e:
                logger.error("LLM client initialization failed", error=str(e))
        else:
            logger.info("LLM client disabled - no API key configured")

    @property
    def is_available(self) -> bool:
        """Check if LLM is available."""
        return self._initialized and self._client is not None

    async def analyze_threat(
        self,
        findings: list[dict[str, Any]],
        context: dict[str, Any] | None = None,
    ) -> LLMResponse:
        """
        Analyze security findings and generate threat interpretation.

        Args:
            findings: List of detection findings
            context: Additional context (event data, correlations)

        Returns:
            LLMResponse with analysis
        """
        if not self.is_available:
            return self._mock_threat_analysis(findings, context)

        start_time = datetime.now(timezone.utc)

        prompt = self._build_threat_analysis_prompt(findings, context)

        try:
            response = self._client.messages.create(
                model=self._settings.llm_model,
                max_tokens=2048,
                messages=[{"role": "user", "content": prompt}],
                system="You are a cybersecurity analyst AI assistant. Analyze security findings and provide clear, actionable threat assessments. Focus on: threat severity, attack vectors, potential impact, and immediate recommendations.",
            )

            end_time = datetime.now(timezone.utc)

            return LLMResponse(
                content=response.content[0].text,
                model=self._settings.llm_model,
                tokens_used=response.usage.input_tokens + response.usage.output_tokens,
                processing_time_ms=(end_time - start_time).total_seconds() * 1000,
            )

        except Exception as e:
            logger.error("LLM threat analysis failed", error=str(e))
            return LLMResponse(
                content="",
                model=self._settings.llm_model,
                success=False,
                error=str(e),
            )

    async def generate_remediation(
        self,
        incident_data: dict[str, Any],
    ) -> LLMResponse:
        """Generate remediation recommendations for an incident."""
        if not self.is_available:
            return self._mock_remediation(incident_data)

        start_time = datetime.now(timezone.utc)

        prompt = self._build_remediation_prompt(incident_data)

        try:
            response = self._client.messages.create(
                model=self._settings.llm_model,
                max_tokens=2048,
                messages=[{"role": "user", "content": prompt}],
                system="You are a cybersecurity incident responder. Provide step-by-step remediation guidance that is practical, prioritized by urgency, and includes both immediate containment actions and long-term fixes.",
            )

            end_time = datetime.now(timezone.utc)

            return LLMResponse(
                content=response.content[0].text,
                model=self._settings.llm_model,
                tokens_used=response.usage.input_tokens + response.usage.output_tokens,
                processing_time_ms=(end_time - start_time).total_seconds() * 1000,
            )

        except Exception as e:
            logger.error("LLM remediation generation failed", error=str(e))
            return LLMResponse(
                content="",
                model=self._settings.llm_model,
                success=False,
                error=str(e),
            )

    async def enrich_ioc(
        self,
        ioc_type: str,
        ioc_value: str,
    ) -> LLMResponse:
        """Provide context and enrichment for an IOC."""
        if not self.is_available:
            return self._mock_ioc_enrichment(ioc_type, ioc_value)

        prompt = f"""Analyze this Indicator of Compromise (IOC):

Type: {ioc_type}
Value: {ioc_value}

Provide:
1. What this IOC type typically indicates
2. Potential threat categories it may be associated with
3. Recommended investigation steps
4. Defensive measures to consider

Keep the response concise and actionable."""

        try:
            response = self._client.messages.create(
                model=self._settings.llm_model,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )

            return LLMResponse(
                content=response.content[0].text,
                model=self._settings.llm_model,
                tokens_used=response.usage.input_tokens + response.usage.output_tokens,
            )

        except Exception as e:
            return LLMResponse(
                content="",
                model=self._settings.llm_model,
                success=False,
                error=str(e),
            )

    async def map_to_mitre(
        self,
        description: str,
        findings: list[dict[str, Any]] | None = None,
    ) -> LLMResponse:
        """Map threat activity to MITRE ATT&CK framework."""
        if not self.is_available:
            return self._mock_mitre_mapping(description)

        findings_text = ""
        if findings:
            findings_text = "\n\nFindings:\n" + "\n".join(
                f"- {f.get('title', 'Unknown')}: {f.get('description', '')}"
                for f in findings
            )

        prompt = f"""Map the following security activity to the MITRE ATT&CK framework:

Activity Description:
{description}
{findings_text}

Identify:
1. Relevant Tactics (e.g., Initial Access, Execution, Persistence)
2. Specific Techniques with IDs (e.g., T1566.001 - Spearphishing Attachment)
3. Confidence level for each mapping
4. Related techniques that may follow in the attack chain

Format as structured analysis."""

        try:
            response = self._client.messages.create(
                model=self._settings.llm_model,
                max_tokens=1536,
                messages=[{"role": "user", "content": prompt}],
                system="You are an expert in the MITRE ATT&CK framework. Provide accurate technique mappings with proper IDs.",
            )

            return LLMResponse(
                content=response.content[0].text,
                model=self._settings.llm_model,
                tokens_used=response.usage.input_tokens + response.usage.output_tokens,
            )

        except Exception as e:
            return LLMResponse(
                content="",
                model=self._settings.llm_model,
                success=False,
                error=str(e),
            )

    def _build_threat_analysis_prompt(
        self,
        findings: list[dict[str, Any]],
        context: dict[str, Any] | None,
    ) -> str:
        """Build prompt for threat analysis."""
        findings_text = "\n".join(
            f"- [{f.get('severity', 'unknown').upper()}] {f.get('title', 'Unknown')}: {f.get('description', '')}"
            for f in findings
        )

        context_text = ""
        if context:
            if "event_type" in context:
                context_text += f"\nEvent Type: {context['event_type']}"
            if "source" in context:
                context_text += f"\nSource: {context['source']}"
            if "risk_score" in context:
                context_text += f"\nRisk Score: {context['risk_score']}/100"

        return f"""Analyze the following security findings and provide a threat assessment:

FINDINGS:
{findings_text}
{context_text}

Provide:
1. **Threat Summary**: One-paragraph overview of what's happening
2. **Severity Assessment**: Your assessment of the overall threat level
3. **Attack Vector**: How the attacker is likely operating
4. **Potential Impact**: What could happen if not addressed
5. **Immediate Actions**: Top 3 actions to take right now
6. **Investigation Leads**: What to look for next"""

    def _build_remediation_prompt(self, incident_data: dict[str, Any]) -> str:
        """Build prompt for remediation recommendations."""
        return f"""Generate remediation recommendations for this security incident:

INCIDENT:
Title: {incident_data.get('title', 'Unknown')}
Severity: {incident_data.get('severity', 'Unknown')}
Description: {incident_data.get('description', 'No description')}

Affected Systems: {', '.join(incident_data.get('affected_systems', ['Unknown']))}
MITRE Techniques: {', '.join(incident_data.get('mitre_techniques', []))}

Provide:
1. **Immediate Containment** (first 15 minutes)
2. **Short-term Actions** (first 24 hours)
3. **Eradication Steps**
4. **Recovery Procedures**
5. **Prevention Measures** (long-term)

Prioritize by urgency and include specific commands or steps where applicable."""

    # ================================================================
    # Mock responses for when LLM is not configured
    # ================================================================

    def _mock_threat_analysis(
        self,
        findings: list[dict[str, Any]],
        context: dict[str, Any] | None,
    ) -> LLMResponse:
        """Provide mock threat analysis when LLM is unavailable."""
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        highest = "low"
        for sev in ["critical", "high", "medium", "low"]:
            if sev in severity_counts:
                highest = sev
                break

        content = f"""## Threat Analysis (Automated)

**Threat Summary:**
Detected {len(findings)} security finding(s) requiring attention. The highest severity level is {highest.upper()}.

**Severity Assessment:**
- Critical: {severity_counts.get('critical', 0)}
- High: {severity_counts.get('high', 0)}
- Medium: {severity_counts.get('medium', 0)}
- Low: {severity_counts.get('low', 0)}

**Immediate Actions:**
1. Review all CRITICAL and HIGH severity findings immediately
2. Isolate affected systems if compromise is suspected
3. Preserve logs and evidence for forensic analysis

**Note:** This is an automated analysis. Enable LLM integration for detailed AI-powered threat interpretation.
"""

        return LLMResponse(
            content=content,
            model="mock",
            tokens_used=0,
        )

    def _mock_remediation(self, incident_data: dict[str, Any]) -> LLMResponse:
        """Provide mock remediation when LLM is unavailable."""
        content = f"""## Remediation Recommendations (Automated)

**Incident:** {incident_data.get('title', 'Unknown')}
**Severity:** {incident_data.get('severity', 'Unknown')}

### Immediate Containment
1. Identify and isolate affected systems
2. Block malicious IPs/domains at firewall
3. Disable compromised user accounts

### Short-term Actions
1. Reset credentials for affected users
2. Scan systems for malware/backdoors
3. Review access logs for lateral movement

### Recovery
1. Restore from clean backups if needed
2. Re-enable services after verification
3. Monitor for recurrence

**Note:** Enable LLM integration for detailed, context-specific recommendations.
"""

        return LLMResponse(
            content=content,
            model="mock",
            tokens_used=0,
        )

    def _mock_ioc_enrichment(self, ioc_type: str, ioc_value: str) -> LLMResponse:
        """Provide mock IOC enrichment."""
        content = f"""## IOC Analysis (Automated)

**Type:** {ioc_type}
**Value:** {ioc_value}

### Investigation Steps
1. Check threat intelligence feeds for this {ioc_type}
2. Search historical logs for related activity
3. Identify all systems that communicated with this indicator

### Defensive Measures
1. Block this {ioc_type} at perimeter
2. Add to detection rules
3. Hunt for similar indicators

**Note:** Enable LLM integration for detailed context.
"""

        return LLMResponse(
            content=content,
            model="mock",
            tokens_used=0,
        )

    def _mock_mitre_mapping(self, description: str) -> LLMResponse:
        """Provide mock MITRE mapping."""
        content = """## MITRE ATT&CK Mapping (Automated)

Based on the activity description, potential mappings include:

### Tactics
- Initial Access
- Execution
- Credential Access

### Techniques
- T1566 - Phishing (if email-related)
- T1110 - Brute Force (if authentication failures)
- T1046 - Network Service Scanning (if port scanning)

**Note:** Enable LLM integration for accurate, context-specific MITRE mappings.
"""

        return LLMResponse(
            content=content,
            model="mock",
            tokens_used=0,
        )


# Singleton
_llm_client: LLMClient | None = None


def get_llm_client() -> LLMClient:
    """Get the global LLM client."""
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient()
    return _llm_client
