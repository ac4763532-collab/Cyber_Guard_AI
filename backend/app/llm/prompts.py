"""
CyberGuard AI - LLM Prompt Templates

Cybersecurity-focused prompt templates for LLM analysis.
"""

from typing import Any

import structlog


logger = structlog.get_logger(__name__)


class PromptBuilder:
    """
    Builder for cybersecurity-focused LLM prompts.

    Provides templates for:
    - Threat analysis
    - Incident investigation
    - Remediation guidance
    - MITRE ATT&CK mapping
    """

    def __init__(self):
        self.templates = self._load_templates()

    def _load_templates(self) -> dict[str, str]:
        """Load prompt templates."""
        return {
            "threat_analysis": """You are analyzing security findings for a SOC analyst.

## Context
{context}

## Findings
{findings}

## Your Task
Provide a structured threat analysis including:
1. Executive summary (2-3 sentences)
2. Threat classification
3. Attack vector analysis
4. Potential impact assessment
5. Recommended immediate actions (prioritized list)
6. Related MITRE ATT&CK techniques

Be specific, actionable, and avoid generic advice.""",

            "incident_response": """You are an incident response specialist.

## Incident Details
Title: {title}
Severity: {severity}
Status: {status}

## Description
{description}

## Affected Assets
{affected_assets}

## Known IOCs
{iocs}

## Your Task
Provide an incident response playbook:
1. Immediate containment steps (first 30 minutes)
2. Investigation checklist
3. Evidence preservation steps
4. Eradication procedures
5. Recovery steps
6. Post-incident recommendations

Include specific commands, queries, or tools where applicable.""",

            "correlation_analysis": """You are analyzing correlated security events.

## Correlated Events
{events}

## Shared Indicators
{shared_indicators}

## Timeline
First seen: {first_seen}
Last seen: {last_seen}
Duration: {duration}

## Your Task
Analyze this correlation and provide:
1. Likely attack scenario narrative
2. Attacker's probable objectives
3. Current stage in the attack lifecycle
4. Predicted next steps by the attacker
5. Critical gaps in visibility
6. Recommended detection enhancements""",

            "email_phishing": """Analyze this suspicious email for phishing indicators.

## Email Details
Subject: {subject}
Sender: {sender}
Reply-To: {reply_to}

## Content
{body}

## URLs Found
{urls}

## Attachments
{attachments}

## Your Task
Provide:
1. Phishing likelihood score (1-10) with justification
2. Identified social engineering tactics
3. Technical indicators of compromise
4. Brand impersonation analysis
5. Recommended user communication
6. Suggested block/allow decision""",

            "log_investigation": """Investigate these security log patterns.

## Log Summary
Source: {source}
Time Range: {time_range}
Event Count: {event_count}

## Pattern Details
{patterns}

## Anomalies Detected
{anomalies}

## Your Task
Provide:
1. Classification of activity (malicious/suspicious/benign)
2. Likely root cause
3. User/system behavior assessment
4. Related activity to investigate
5. Log queries for deeper analysis
6. Recommended response actions""",
        }

    def build(
        self,
        template_name: str,
        **kwargs: Any,
    ) -> str:
        """
        Build a prompt from a template.

        Args:
            template_name: Name of the template to use
            **kwargs: Values to fill in the template

        Returns:
            Formatted prompt string
        """
        template = self.templates.get(template_name)
        if not template:
            raise ValueError(f"Unknown template: {template_name}")

        # Fill in provided values, use placeholders for missing ones
        try:
            return template.format(**kwargs)
        except KeyError as e:
            logger.warning(
                "Missing template variable",
                template=template_name,
                missing=str(e),
            )
            # Return partial fill
            for key in kwargs:
                template = template.replace(f"{{{key}}}", str(kwargs[key]))
            return template

    def get_system_prompt(self, role: str = "analyst") -> str:
        """Get system prompt for different roles."""
        prompts = {
            "analyst": """You are an expert cybersecurity analyst AI assistant. Your role is to:
- Analyze security events and findings with precision
- Provide actionable, prioritized recommendations
- Map threats to the MITRE ATT&CK framework
- Consider both immediate tactical response and strategic improvements
- Communicate clearly for both technical and non-technical audiences

Always cite specific evidence for your conclusions. If uncertain, express confidence levels.""",

            "responder": """You are a cybersecurity incident responder. Your role is to:
- Guide rapid containment and eradication of threats
- Provide specific, executable remediation steps
- Prioritize actions by urgency and impact
- Consider evidence preservation requirements
- Plan for business continuity during response

Focus on practical steps that can be executed immediately.""",

            "hunter": """You are a threat hunter specialist. Your role is to:
- Identify patterns that may indicate advanced persistent threats
- Develop hypotheses about attacker behavior
- Suggest proactive hunting queries and techniques
- Connect disparate signals into attack narratives
- Anticipate attacker next moves

Think like an attacker to better defend.""",
        }
        return prompts.get(role, prompts["analyst"])

    def list_templates(self) -> list[str]:
        """List available templates."""
        return list(self.templates.keys())


# Singleton
_prompt_builder: PromptBuilder | None = None


def get_prompt_builder() -> PromptBuilder:
    """Get the global prompt builder."""
    global _prompt_builder
    if _prompt_builder is None:
        _prompt_builder = PromptBuilder()
    return _prompt_builder
