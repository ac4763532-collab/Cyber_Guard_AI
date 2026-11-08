"""
CyberGuard AI — Log Analysis Agent Package

The Log Analysis Agent detects suspicious activity in operating system,
application, and database logs. It's the first agent in the detection
pipeline and the primary consumer of events with
``event.category=AUTHENTICATION | AUTHORIZATION | FILE | PROCESS |
SYSTEM | DATABASE``.

The agent is stateless and idempotent. Its rules query the DB for
recent related events (e.g. "how many failed logins from this IP?") and
produce findings via ``finding_service.create_finding`` (which
deduplicates by fingerprint).

Public API:
    from app.agents.log_analysis import LogAnalysisAgent
"""

from app.agents.log_analysis.agent import LogAnalysisAgent

__all__ = ["LogAnalysisAgent"]