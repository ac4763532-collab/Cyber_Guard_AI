import pytest
from unittest.mock import MagicMock
from app.api.v1.assistant import get_assistant_status
from app.models.enums import EventSeverity, CasePriority, FindingCategory
from app.models.case import SecurityCase

def test_event_severity_imported():
    assert EventSeverity.LOW == "low"
    assert EventSeverity.MEDIUM == "medium"
    assert EventSeverity.HIGH == "high"

def test_assistant_status_available():
    mock_user = MagicMock()
    status = get_assistant_status(current_user=mock_user)
    assert status["available"] is True
    assert status["provider"] in ("Groq LPU (Llama 3.3)", "Google Gemini Flash", "CyberGuard AI Engine")
    assert "connected and ready" in status["message"] or "active and ready" in status["message"]
