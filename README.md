---
title: CyberGuard
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: gradio
sdk_version: 4.44.0
app_file: app.py
pinned: false
---

# 🛡️ CyberGuard AI — Unified Security Engine & API Gateway

Zero-Cost SIEM, Endpoint Detection & Dual-Provider AI Threat Intelligence System.

## Architecture
- **API Runtime**: FastAPI high-concurrency async ASGI engine.
- **Diagnostics Dashboard**: Gradio SOC Command Center.
- **Database**: Neon Serverless PostgreSQL with connection pooling.
- **LLM Pipeline**: Google Gemini 2.5 Flash Lite (Primary) with Groq LPU failover (Fallback).
- **Public API Base**: `/api/v1`
- **Swagger Documentation**: `/docs`
- **Health Telemetry**: `/health`
