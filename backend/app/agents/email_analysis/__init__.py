"""
CyberGuard AI — Email Analysis Agent Package

Detects phishing, spam, malicious URLs, and sender impersonation in
email events. Consumes events with ``event.category=EMAIL``.

The agent runs six deterministic rules against each email:

    1. Authentication failure (SPF/DKIM/DMARC)
    2. Suspicious URL (shorteners, IP-based, sketchy TLDs)
    3. Dangerous attachment (executable, macro-enabled, double-extension)
    4. Sender impersonation (display-name spoof, lookalike domain)
    5. Phishing language (urgency, credential requests, financial lures)
    6. Reply-to mismatch (From domain ≠ Reply-To domain)

ML classification (scikit-learn) is a planned extension. When the
trained model is added to ``rules.py``, it becomes a 7th rule with no
changes to the agent or runtime.

Public API:
    from app.agents.email_analysis import EmailAnalysisAgent
"""

from app.agents.email_analysis.agent import EmailAnalysisAgent

__all__ = ["EmailAnalysisAgent"]