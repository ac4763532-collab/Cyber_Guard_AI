"""
CyberGuard AI - Enhanced LLM Client

Professional-grade Claude API integration with:
- Async operations
- Streaming support
- Structured JSON output
- Retry logic with exponential backoff
- Token usage tracking
- Prompt caching
"""

from datetime import datetime, timezone
from typing import Any, AsyncIterator
from uuid import uuid4
import asyncio
import json

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
    input_tokens: int = 0
    output_tokens: int = 0
    processing_time_ms: float = 0.0
    cached: bool = False

    # Status
    success: bool = True
    error: str | None = None


class LLMUsageStats(BaseModel):
    """Track LLM usage statistics."""
    total_requests: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost_usd: float = 0.0
    cache_hits: int = 0
    errors: int = 0


# Pricing per 1M tokens (as of 2025)
MODEL_PRICING = {
    "claude-sonnet-4-20250514": {"input": 3.0, "output": 15.0},
    "claude-opus-4-20250514": {"input": 15.0, "output": 75.0},
    "claude-3-5-sonnet-20241022": {"input": 3.0, "output": 15.0},
    "claude-3-opus-20240229": {"input": 15.0, "output": 75.0},
}


class EnhancedLLMClient:
    """
    Enhanced LLM Client for Claude API integration.

    Features:
    - Async operations for non-blocking I/O
    - Streaming support for real-time responses
    - Structured JSON output mode
    - Automatic retry with exponential backoff
    - Token usage and cost tracking
    - Cybersecurity-focused prompts
    """

    def __init__(self):
        self._settings = get_settings()
        self._client = None
        self._async_client = None
        self._initialized = False
        self._usage_stats = LLMUsageStats()

        # Retry configuration
        self._max_retries = 3
        self._base_delay = 1.0  # seconds

        self._init_client()

    def _init_client(self) -> None:
        """Initialize Anthropic client."""
        if not self._settings.anthropic_api_key:
            logger.info("LLM client disabled - no API key configured")
            return

        try:
            import anthropic

            # Sync client for compatibility
            self._client = anthropic.Anthropic(
                api_key=self._settings.anthropic_api_key
            )

            # Async client for better performance
            self._async_client = anthropic.AsyncAnthropic(
                api_key=self._settings.anthropic_api_key
            )

            self._initialized = True
            logger.info(
                "Enhanced LLM client initialized",
                model=self._settings.llm_model,
                async_enabled=True
            )

        except ImportError:
            logger.warning("anthropic package not installed - run: pip install anthropic")
        except Exception as e:
            logger.error("LLM client initialization failed", error=str(e))

    @property
    def is_available(self) -> bool:
        """Check if LLM is available."""
        return self._initialized and self._async_client is not None

    @property
    def usage_stats(self) -> LLMUsageStats:
        """Get current usage statistics."""
        return self._usage_stats

    def _calculate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Calculate cost in USD based on token usage."""
        pricing = MODEL_PRICING.get(self._settings.llm_model, {"input": 3.0, "output": 15.0})
        input_cost = (input_tokens / 1_000_000) * pricing["input"]
        output_cost = (output_tokens / 1_000_000) * pricing["output"]
        return input_cost + output_cost

    async def _retry_with_backoff(self, func, *args, **kwargs) -> Any:
        """Execute function with exponential backoff retry."""
        last_exception = None

        for attempt in range(self._max_retries):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                error_str = str(e).lower()

                # Don't retry on auth errors or invalid requests
                if "authentication" in error_str or "invalid" in error_str:
                    raise

                # Retry on rate limits and server errors
                if attempt < self._max_retries - 1:
                    delay = self._base_delay * (2 ** attempt)
                    logger.warning(
                        "LLM request failed, retrying",
                        attempt=attempt + 1,
                        delay=delay,
                        error=str(e)
                    )
                    await asyncio.sleep(delay)

        self._usage_stats.errors += 1
        raise last_exception

    async def analyze_threat(
        self,
        findings: list[dict[str, Any]],
        context: dict[str, Any] | None = None,
        structured_output: bool = False,
    ) -> LLMResponse:
        """
        Analyze security findings and generate threat interpretation.

        Args:
            findings: List of detection findings
            context: Additional context (event data, correlations)
            structured_output: Return JSON-structured analysis

        Returns:
            LLMResponse with analysis
        """
        if not self.is_available:
            return self._mock_threat_analysis(findings, context)

        start_time = datetime.now(timezone.utc)
        prompt = self._build_threat_analysis_prompt(findings, context, structured_output)

        system_prompt = """You are an expert cybersecurity analyst AI assistant specializing in threat detection and analysis.

Your role is to:
- Analyze security findings with precision and accuracy
- Provide actionable, prioritized recommendations
- Map threats to MITRE ATT&CK framework techniques
- Consider both immediate tactical response and strategic improvements
- Communicate clearly with specific evidence for all conclusions

Always express confidence levels when uncertain. Be concise but thorough."""

        try:
            response = await self._retry_with_backoff(
                self._async_client.messages.create,
                model=self._settings.llm_model,
                max_tokens=2048,
                system=system_prompt,
                messages=[{"role": "user", "content": prompt}],
            )

            end_time = datetime.now(timezone.utc)
            processing_time = (end_time - start_time).total_seconds() * 1000

            # Update usage stats
            input_tokens = response.usage.input_tokens
            output_tokens = response.usage.output_tokens
            self._usage_stats.total_requests += 1
            self._usage_stats.total_input_tokens += input_tokens
            self._usage_stats.total_output_tokens += output_tokens
            self._usage_stats.total_cost_usd += self._calculate_cost(input_tokens, output_tokens)

            content = response.content[0].text

            # Parse structured output if requested
            structured_data = None
            if structured_output:
                try:
                    # Try to extract JSON from response
                    json_start = content.find('{')
                    json_end = content.rfind('}') + 1
                    if json_start != -1 and json_end > json_start:
                        structured_data = json.loads(content[json_start:json_end])
                except json.JSONDecodeError:
                    logger.warning("Failed to parse structured output as JSON")

            return LLMResponse(
                content=content,
                structured_data=structured_data,
                model=self._settings.llm_model,
                tokens_used=input_tokens + output_tokens,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                processing_time_ms=processing_time,
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
        """Generate step-by-step remediation for an incident."""
        if not self.is_available:
            return self._mock_remediation(incident_data)

        start_time = datetime.now(timezone.utc)
        prompt = self._build_remediation_prompt(incident_data)

        system_prompt = """You are a cybersecurity incident responder with expertise in containment, eradication, and recovery.

Your role is to:
- Provide specific, executable remediation steps
- Prioritize actions by urgency and impact
- Include actual commands, queries, and tool recommendations
- Consider evidence preservation requirements
- Plan for business continuity during response

Focus on practical steps that can be executed immediately by a SOC team."""

        try:
            response = await self._retry_with_backoff(
                self._async_client.messages.create,
                model=self._settings.llm_model,
                max_tokens=2048,
                system=system_prompt,
                messages=[{"role": "user", "content": prompt}],
            )

            end_time = datetime.now(timezone.utc)
            processing_time = (end_time - start_time).total_seconds() * 1000

            input_tokens = response.usage.input_tokens
            output_tokens = response.usage.output_tokens
            self._usage_stats.total_requests += 1
            self._usage_stats.total_input_tokens += input_tokens
            self._usage_stats.total_output_tokens += output_tokens
            self._usage_stats.total_cost_usd += self._calculate_cost(input_tokens, output_tokens)

            return LLMResponse(
                content=response.content[0].text,
                model=self._settings.llm_model,
                tokens_used=input_tokens + output_tokens,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                processing_time_ms=processing_time,
            )

        except Exception as e:
            logger.error("LLM remediation generation failed", error=str(e))
            return LLMResponse(
                content="",
                model=self._settings.llm_model,
                success=False,
                error=str(e),
            )

    async def stream_analysis(
        self,
        prompt: str,
        system_prompt: str | None = None,
    ) -> AsyncIterator[str]:
        """
        Stream LLM response for real-time display.

        Yields chunks of text as they are generated.
        """
        if not self.is_available:
            yield "LLM not available - streaming disabled"
            return

        if system_prompt is None:
            system_prompt = "You are a cybersecurity analyst AI assistant."

        try:
            async with self._async_client.messages.stream(
                model=self._settings.llm_model,
                max_tokens=2048,
                system=system_prompt,
                messages=[{"role": "user", "content": prompt}],
            ) as stream:
                async for text in stream.text_stream:
                    yield text

        except Exception as e:
            logger.error("LLM streaming failed", error=str(e))
            yield f"\n\n[Error: {str(e)}]"

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
            findings_text = "\n\nRelated Findings:\n" + "\n".join(
                f"- [{f.get('severity', 'unknown').upper()}] {f.get('title', 'Unknown')}: {f.get('description', '')}"
                for f in findings
            )

        prompt = f"""Map the following security activity to the MITRE ATT&CK framework:

## Activity Description
{description}
{findings_text}

## Required Output
Provide a JSON response with this structure:
{{
    "tactics": [
        {{"id": "TAxxxx", "name": "Tactic Name", "confidence": "high/medium/low"}}
    ],
    "techniques": [
        {{"id": "Txxxx.xxx", "name": "Technique Name", "confidence": "high/medium/low", "evidence": "specific evidence"}}
    ],
    "attack_chain": ["T1xxx → T1yyy → T1zzz"],
    "recommendations": ["recommendation 1", "recommendation 2"]
}}

Be specific with technique IDs and provide evidence for each mapping."""

        try:
            response = await self._retry_with_backoff(
                self._async_client.messages.create,
                model=self._settings.llm_model,
                max_tokens=1536,
                system="You are a MITRE ATT&CK framework expert. Provide accurate technique mappings with proper IDs and confidence levels.",
                messages=[{"role": "user", "content": prompt}],
            )

            content = response.content[0].text
            input_tokens = response.usage.input_tokens
            output_tokens = response.usage.output_tokens

            # Track usage
            self._usage_stats.total_requests += 1
            self._usage_stats.total_input_tokens += input_tokens
            self._usage_stats.total_output_tokens += output_tokens
            self._usage_stats.total_cost_usd += self._calculate_cost(input_tokens, output_tokens)

            # Try to parse JSON
            structured_data = None
            try:
                json_start = content.find('{')
                json_end = content.rfind('}') + 1
                if json_start != -1 and json_end > json_start:
                    structured_data = json.loads(content[json_start:json_end])
            except json.JSONDecodeError:
                pass

            return LLMResponse(
                content=content,
                structured_data=structured_data,
                model=self._settings.llm_model,
                tokens_used=input_tokens + output_tokens,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            )

        except Exception as e:
            logger.error("MITRE mapping failed", error=str(e))
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

**Type:** {ioc_type}
**Value:** {ioc_value}

Provide a JSON response:
{{
    "threat_category": "malware/phishing/c2/scanning/etc",
    "risk_level": "critical/high/medium/low",
    "confidence": 0.0-1.0,
    "context": "what this IOC typically indicates",
    "related_threats": ["threat1", "threat2"],
    "investigation_steps": ["step1", "step2"],
    "defensive_actions": ["action1", "action2"],
    "references": ["reference URLs or threat intel sources"]
}}

Be specific and provide actionable intelligence."""

        try:
            response = await self._retry_with_backoff(
                self._async_client.messages.create,
                model=self._settings.llm_model,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )

            content = response.content[0].text
            input_tokens = response.usage.input_tokens
            output_tokens = response.usage.output_tokens

            self._usage_stats.total_requests += 1
            self._usage_stats.total_input_tokens += input_tokens
            self._usage_stats.total_output_tokens += output_tokens
            self._usage_stats.total_cost_usd += self._calculate_cost(input_tokens, output_tokens)

            # Parse JSON
            structured_data = None
            try:
                json_start = content.find('{')
                json_end = content.rfind('}') + 1
                if json_start != -1 and json_end > json_start:
                    structured_data = json.loads(content[json_start:json_end])
            except json.JSONDecodeError:
                pass

            return LLMResponse(
                content=content,
                structured_data=structured_data,
                model=self._settings.llm_model,
                tokens_used=input_tokens + output_tokens,
            )

        except Exception as e:
            return LLMResponse(
                content="",
                model=self._settings.llm_model,
                success=False,
                error=str(e),
            )

    async def chat(
        self,
        message: str,
        conversation_history: list[dict[str, str]] | None = None,
    ) -> LLMResponse:
        """
        General cybersecurity chat interface.

        Supports conversation history for multi-turn interactions.
        """
        if not self.is_available:
            return LLMResponse(
                content="LLM not available. Please configure ANTHROPIC_API_KEY.",
                model="mock",
                success=False,
                error="LLM not configured",
            )

        start_time = datetime.now(timezone.utc)

        messages = []
        if conversation_history:
            messages.extend(conversation_history)
        messages.append({"role": "user", "content": message})

        system_prompt = """You are CyberGuard AI, an expert cybersecurity assistant.

You help security analysts with:
- Threat analysis and investigation
- Incident response guidance
- MITRE ATT&CK mapping
- Log analysis and hunting queries
- Security best practices

Be precise, cite evidence, and provide actionable recommendations.
When uncertain, express confidence levels."""

        try:
            response = await self._retry_with_backoff(
                self._async_client.messages.create,
                model=self._settings.llm_model,
                max_tokens=2048,
                system=system_prompt,
                messages=messages,
            )

            end_time = datetime.now(timezone.utc)

            input_tokens = response.usage.input_tokens
            output_tokens = response.usage.output_tokens

            self._usage_stats.total_requests += 1
            self._usage_stats.total_input_tokens += input_tokens
            self._usage_stats.total_output_tokens += output_tokens
            self._usage_stats.total_cost_usd += self._calculate_cost(input_tokens, output_tokens)

            return LLMResponse(
                content=response.content[0].text,
                model=self._settings.llm_model,
                tokens_used=input_tokens + output_tokens,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                processing_time_ms=(end_time - start_time).total_seconds() * 1000,
            )

        except Exception as e:
            logger.error("Chat failed", error=str(e))
            return LLMResponse(
                content="",
                model=self._settings.llm_model,
                success=False,
                error=str(e),
            )

    # ================================================================
    # Prompt Builders
    # ================================================================

    def _build_threat_analysis_prompt(
        self,
        findings: list[dict[str, Any]],
        context: dict[str, Any] | None,
        structured: bool = False,
    ) -> str:
        """Build prompt for threat analysis."""
        findings_text = "\n".join(
            f"- [{f.get('severity', 'unknown').upper()}] **{f.get('title', 'Unknown')}**: {f.get('description', '')}"
            for f in findings
        )

        context_text = ""
        if context:
            context_items = []
            if "event_type" in context:
                context_items.append(f"- Event Type: {context['event_type']}")
            if "source" in context:
                context_items.append(f"- Source: {context['source']}")
            if "risk_score" in context:
                context_items.append(f"- Risk Score: {context['risk_score']}/100")
            if "timestamp" in context:
                context_items.append(f"- Timestamp: {context['timestamp']}")
            context_text = "\n## Context\n" + "\n".join(context_items)

        output_format = ""
        if structured:
            output_format = """

## Output Format
Return a JSON object:
{
    "summary": "executive summary",
    "severity": "critical/high/medium/low",
    "confidence": 0.0-1.0,
    "threat_type": "classification",
    "attack_vector": "how the attack works",
    "impact": "potential business impact",
    "immediate_actions": ["action1", "action2", "action3"],
    "mitre_techniques": ["T1xxx", "T1yyy"],
    "investigation_queries": ["query1", "query2"]
}"""

        return f"""Analyze these security findings and provide a threat assessment:

## Findings
{findings_text}
{context_text}

## Required Analysis
1. **Executive Summary**: 2-3 sentence overview
2. **Threat Classification**: Type and severity assessment
3. **Attack Vector**: How the attacker is likely operating
4. **Potential Impact**: Business and security implications
5. **Immediate Actions**: Top 3 prioritized response actions
6. **MITRE ATT&CK**: Relevant techniques and tactics
7. **Investigation Leads**: What to investigate next
{output_format}"""

    def _build_remediation_prompt(self, incident_data: dict[str, Any]) -> str:
        """Build prompt for remediation recommendations."""
        return f"""Generate an incident response playbook for this security incident:

## Incident Details
- **Title**: {incident_data.get('title', 'Unknown')}
- **Severity**: {incident_data.get('severity', 'Unknown')}
- **Status**: {incident_data.get('status', 'Unknown')}
- **Description**: {incident_data.get('description', 'No description')}

## Affected Systems
{', '.join(incident_data.get('affected_systems', ['Unknown']))}

## Identified Techniques
{', '.join(incident_data.get('mitre_techniques', ['None identified']))}

## IOCs
{', '.join(incident_data.get('iocs', ['None']))}

## Required Playbook Sections

### 1. Immediate Containment (first 15 minutes)
Specific steps to stop the bleeding

### 2. Evidence Preservation
What to collect before making changes

### 3. Investigation Checklist
Key questions to answer

### 4. Eradication Steps
How to remove the threat

### 5. Recovery Procedures
Safe return to normal operations

### 6. Post-Incident Actions
Prevention and documentation

Include specific commands, tools, and queries where applicable."""

    # ================================================================
    # Mock Responses (when LLM is unavailable)
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

        highest = "info"
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in severity_counts:
                highest = sev
                break

        content = f"""## Threat Analysis (Automated - LLM Unavailable)

**⚠️ Note**: This is an automated analysis. Configure ANTHROPIC_API_KEY for AI-powered insights.

### Executive Summary
Detected **{len(findings)}** security finding(s). Highest severity: **{highest.upper()}**

### Severity Breakdown
| Severity | Count |
|----------|-------|
| Critical | {severity_counts.get('critical', 0)} |
| High | {severity_counts.get('high', 0)} |
| Medium | {severity_counts.get('medium', 0)} |
| Low | {severity_counts.get('low', 0)} |

### Immediate Actions
1. Review all CRITICAL and HIGH severity findings
2. Isolate affected systems if compromise is suspected
3. Preserve logs and evidence for forensic analysis

### Next Steps
Enable LLM integration for detailed AI-powered analysis:
```bash
# Add to backend/.env
ANTHROPIC_API_KEY=your_api_key_here
```
"""
        return LLMResponse(content=content, model="mock", tokens_used=0)

    def _mock_remediation(self, incident_data: dict[str, Any]) -> LLMResponse:
        """Provide mock remediation when LLM is unavailable."""
        content = f"""## Remediation Playbook (Automated)

**⚠️ Note**: Configure ANTHROPIC_API_KEY for AI-tailored remediation.

### Incident: {incident_data.get('title', 'Unknown')}
**Severity**: {incident_data.get('severity', 'Unknown')}

### Immediate Containment
1. Identify and isolate affected systems
2. Block malicious IPs/domains at firewall
3. Disable compromised user accounts

### Evidence Preservation
1. Capture memory dumps before rebooting
2. Export relevant logs to secure storage
3. Screenshot active sessions/connections

### Eradication
1. Run full antimalware scans
2. Remove malicious files/persistence mechanisms
3. Reset compromised credentials

### Recovery
1. Restore from clean backups
2. Re-enable services incrementally
3. Monitor for recurrence (24-48 hours)
"""
        return LLMResponse(content=content, model="mock", tokens_used=0)

    def _mock_mitre_mapping(self, description: str) -> LLMResponse:
        """Provide mock MITRE mapping."""
        content = """## MITRE ATT&CK Mapping (Automated)

**⚠️ Note**: Configure ANTHROPIC_API_KEY for accurate AI mappings.

### Potential Tactics
- Initial Access (TA0001)
- Execution (TA0002)
- Credential Access (TA0006)

### Common Techniques
- T1566 - Phishing
- T1110 - Brute Force
- T1046 - Network Service Scanning

### Recommendation
Enable LLM for context-specific MITRE mappings with evidence.
"""
        structured_data = {
            "tactics": [
                {"id": "TA0001", "name": "Initial Access", "confidence": "low"},
                {"id": "TA0002", "name": "Execution", "confidence": "low"},
            ],
            "techniques": [
                {"id": "T1566", "name": "Phishing", "confidence": "low", "evidence": "Automated suggestion"},
            ],
            "attack_chain": [],
            "recommendations": ["Enable LLM for accurate mapping"],
        }
        return LLMResponse(
            content=content,
            structured_data=structured_data,
            model="mock",
            tokens_used=0
        )

    def _mock_ioc_enrichment(self, ioc_type: str, ioc_value: str) -> LLMResponse:
        """Provide mock IOC enrichment."""
        content = f"""## IOC Analysis (Automated)

**Type**: {ioc_type}
**Value**: {ioc_value}

### Investigation Steps
1. Check threat intelligence feeds
2. Search historical logs
3. Identify affected systems

### Defensive Actions
1. Block at perimeter
2. Add to detection rules
3. Hunt for related indicators

**⚠️ Configure ANTHROPIC_API_KEY for detailed threat intelligence.**
"""
        return LLMResponse(content=content, model="mock", tokens_used=0)


# Singleton
_enhanced_llm_client: EnhancedLLMClient | None = None


def get_enhanced_llm_client() -> EnhancedLLMClient:
    """Get the global enhanced LLM client."""
    global _enhanced_llm_client
    if _enhanced_llm_client is None:
        _enhanced_llm_client = EnhancedLLMClient()
    return _enhanced_llm_client


# Keep backward compatibility
def get_llm_client() -> EnhancedLLMClient:
    """Get the LLM client (alias for backward compatibility)."""
    return get_enhanced_llm_client()
