"""
CyberGuard AI — Hugging Face Spaces Deployment Gateway
============================================================================
Zero-Cost SOC Intelligence Gateway combining FastAPI with Gradio Dashboard.
Provisioned for Hugging Face Spaces (CPU Basic, 16 GB RAM).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure 'backend' directory is in sys.path
BASE_DIR = Path(__file__).resolve().parent
BACKEND_DIR = BASE_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import gradio as gr
from app.main import app as fastapi_app
from app.core.config import settings

def get_system_health():
    """Retrieve operational status for the Gradio diagnostics board."""
    from app.db.session import health_check
    
    try:
        db_ok = health_check()
        db_status = "🟢 Connected (Neon Serverless PostgreSQL)" if db_ok else "🔴 Disconnected"
    except Exception as e:
        db_status = f"🔴 Error: {str(e)[:50]}"
    
    gemini_key = settings.GEMINI_API_KEY.get_secret_value() if hasattr(settings.GEMINI_API_KEY, "get_secret_value") else str(settings.GEMINI_API_KEY)
    groq_key = settings.GROQ_API_KEY.get_secret_value() if hasattr(settings.GROQ_API_KEY, "get_secret_value") else str(settings.GROQ_API_KEY)
    
    return {
        "Status": "ONLINE",
        "Database": db_status,
        "Primary LLM (Gemini Flash Lite)": "🟢 Active" if gemini_key else "⚠️ Missing Key",
        "Fallback LLM (Groq Qwen 27B)": "🟢 Active" if groq_key else "⚠️ Missing Key",
        "Environment": settings.APP_ENV,
        "API Base": "/api/v1",
        "Documentation": "/docs",
    }

def analyze_event_preview(event_code: str, details: str):
    """Test AI Security Intelligence explainer directly from the dashboard."""
    from app.llm.free_llm_client import free_llm_client
    
    if not event_code or not details:
        return "Please provide both an Event ID and Context details."
    
    prompt = (
        f"Analyze Windows Security Event ID {event_code}: {details}. "
        f"Provide a concise 2-sentence SOC explanation, potential threat category, and recommended analyst action."
    )
    
    res = free_llm_client.generate(
        system_prompt="You are CyberGuard AI Senior SOC Analyst. Be concise, highly professional, and actionable.",
        user_prompt=prompt,
        max_tokens=300,
        temperature=0.2,
    )
    
    if res["success"]:
        return f"🤖 Provider: {res['provider'].upper()} ({res['model']})\n\n{res['text']}"
    return f"❌ Analysis Failed: {res.get('error', 'Unknown error')}"

# ────────────────────────────────────────────────────────────────────────────
# Gradio Blocks Dashboard Interface
# ────────────────────────────────────────────────────────────────────────────

with gr.Blocks(title="CyberGuard AI — SOC Intelligence Gateway", theme=gr.themes.Soft()) as demo:
    gr.Markdown("# 🛡️ CyberGuard AI — Unified Security Engine")
    gr.Markdown(
        "**Production SIEM & Threat Intelligence API Gateway** running on Hugging Face Spaces.\n"
        "Serves RESTful endpoints to the Cloudflare Pages web application and endpoint telemetry collectors."
    )
    
    with gr.Row():
        with gr.Column(scale=1):
            gr.Markdown("### 📡 Quick Endpoints")
            gr.Markdown(
                "- 📖 **Interactive Swagger UI**: [/docs](/docs)\n"
                "- 📑 **ReDoc Documentation**: [/redoc](/redoc)\n"
                "- 🩺 **Health Check**: [/health](/health)\n"
                "- 🔍 **API Discovery**: [/api](/api)\n"
                "- 🌐 **Base API URL**: `/api/v1`"
            )
        
        with gr.Column(scale=2):
            gr.Markdown("### ⚙️ System Telemetry & Health")
            status_display = gr.JSON(value=get_system_health, label="Live Engine Status")
            refresh_btn = gr.Button("🔄 Refresh Health Status", size="sm")
            refresh_btn.click(fn=get_system_health, outputs=status_display)

    with gr.Accordion("🧪 Live Security Event Explainer (Gemini Flash Lite / Groq Dual-Failover)", open=False):
        gr.Markdown("Evaluate real-time AI security intelligence using the integrated Zero-Cost LLM pipeline:")
        with gr.Row():
            event_id_input = gr.Textbox(value="4625", label="Event ID", scale=1)
            event_ctx_input = gr.Textbox(
                value="An account failed to log on. Substatus 0xc000006a (wrong password) repeated 12 times in 60s from IP 192.168.1.105.",
                label="Event Context / Telemetry Payload",
                scale=3
            )
        explain_run_btn = gr.Button("🔍 Run AI Security Analysis", variant="primary")
        explain_result_display = gr.Textbox(label="AI SOC Analyst Assessment", lines=5)
        explain_run_btn.click(
            fn=analyze_event_preview,
            inputs=[event_id_input, event_ctx_input],
            outputs=explain_result_display
        )

# Mount Gradio dashboard at root "/" on the FastAPI application
app = gr.mount_gradio_app(fastapi_app, demo, path="/")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 7860))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)
