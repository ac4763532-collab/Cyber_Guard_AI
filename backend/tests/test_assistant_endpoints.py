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


def test_assistant_message_intent_routing():
    from app.api.v1.assistant import send_assistant_message, AssistantMessageRequest
    from app.models.alert import SecurityAlert
    from app.models.finding import AgentFinding
    import uuid

    mock_db = MagicMock()
    mock_user = MagicMock()
    mock_user.id = uuid.uuid4()

    # Simulate existing alerts in workspace
    mock_alert = MagicMock()
    mock_alert.title = "Threat intelligence match: Malicious domain: naukri.com"
    mock_alert.severity.value = "high"
    mock_alert.rule_id = "RUL-MAL-001"

    # Mock DB query results
    mock_execute = MagicMock()
    mock_execute.scalar.return_value = 1
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = [mock_alert]
    mock_scalars.first.return_value = MagicMock(id=uuid.uuid4())
    mock_execute.scalars.return_value = mock_scalars
    mock_db.execute.return_value = mock_execute

    # 1. Test greeting "hi"
    res_hi = send_assistant_message(
        payload=AssistantMessageRequest(message="hi"),
        db=mock_db,
        current_user=mock_user,
    )
    assert "Hello" in res_hi.reply or "CyberGuard AI Security Assistant" in res_hi.reply
    assert "Based on your verified telemetry" not in res_hi.reply

    # 2. Test Gmail detection query
    res_gmail = send_assistant_message(
        payload=AssistantMessageRequest(message="how gmail detect"),
        db=mock_db,
        current_user=mock_user,
    )
    assert "Gmail" in res_gmail.reply or "email" in res_gmail.reply
    assert "Based on your verified telemetry" not in res_gmail.reply

    # 3. Test CyberGuard assistance query
    res_cg = send_assistant_message(
        payload=AssistantMessageRequest(message="can you help me to answere related cyberguard"),
        db=mock_db,
        current_user=mock_user,
    )
    assert "CyberGuard" in res_cg.reply
    assert "Based on your verified telemetry" not in res_cg.reply
