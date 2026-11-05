"""
CyberGuard AI - API v1 Router

Aggregates all v1 API routes into a single router.
"""

from fastapi import APIRouter

from app.api.v1 import health, analysis, detection, correlation, llm, ws, alerts, events, auth, reports, gmail, metrics, feedback, training, logs, notifications, threat_intel, incidents

# Create the main v1 router
api_router = APIRouter()

# Include sub-routers
api_router.include_router(health.router)
api_router.include_router(analysis.router)  # Milestone 4
api_router.include_router(detection.router)  # Milestone 8
api_router.include_router(correlation.router)  # Milestone 10
api_router.include_router(llm.router)  # Milestone 12
api_router.include_router(ws.router)  # Milestone 14
api_router.include_router(alerts.router)  # Milestone 15
api_router.include_router(events.router)  # Milestone 16
api_router.include_router(events.findings_router)  # Phase 1 - Findings persistence
api_router.include_router(auth.router)  # Milestone 17
api_router.include_router(reports.router)  # Milestone 18
api_router.include_router(gmail.router)  # Gmail Integration
api_router.include_router(metrics.router)  # Step 10 - Metrics
api_router.include_router(feedback.router)  # Step 12 - Feedback
api_router.include_router(training.router)  # Step 13 - Continuous Learning
api_router.include_router(logs.router)  # Step 8 - Log Analysis
api_router.include_router(notifications.router)  # Phase 10 - Notification inbox
api_router.include_router(threat_intel.router)  # Gate 1 - Threat Intelligence Agent
api_router.include_router(incidents.router)  # Tenant-scoped incident lifecycle
# web_ingest no longer registers a router (STEP 9 - web_application source
# type removed; app.api.v1.web_ingest now only exports shared ingestion-key
# auth helpers reused by logs.router's generic /ingest routes).

# Future routers will be added here as milestones are completed:
# api_router.include_router(auth.router)      # Milestone 17
# api_router.include_router(events.router)    # Milestone 15
# api_router.include_router(alerts.router)    # Milestone 16
# api_router.include_router(agents.router)    # Milestones 5-7
# api_router.include_router(reports.router)   # Milestone 18
