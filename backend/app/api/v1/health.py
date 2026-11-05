"""
CyberGuard AI - Health Check Endpoints

Provides system health status for monitoring and dashboard display.
Includes liveness, readiness, and detailed health checks.
"""

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Response
from pydantic import BaseModel, Field

from app.config import settings


router = APIRouter(prefix="/health", tags=["Health"])


class ComponentStatus(BaseModel):
    """Status of an individual system component."""

    name: str = Field(..., description="Component name")
    status: Literal["online", "offline", "degraded", "pending"] = Field(
        ..., description="Component health status"
    )
    message: str | None = Field(None, description="Optional status message")
    latency_ms: float | None = Field(None, description="Response latency in milliseconds")
    last_run: str | None = None
    last_successful_run: str | None = None
    total_analyzed: int | None = None
    error_count: int | None = None


class HealthResponse(BaseModel):
    """Complete health check response."""

    status: Literal["healthy", "unhealthy", "degraded"] = Field(
        ..., description="Overall system health status"
    )
    timestamp: datetime = Field(..., description="Health check timestamp")
    version: str = Field(..., description="Application version")
    environment: str = Field(..., description="Deployment environment")
    components: dict[str, ComponentStatus] = Field(
        default_factory=dict, description="Individual component statuses"
    )


class SimpleHealthResponse(BaseModel):
    """Simple health check for load balancers."""

    status: str = Field(..., description="System status")
    timestamp: datetime = Field(..., description="Check timestamp")
    version: str = Field(..., description="Application version")


class LivenessResponse(BaseModel):
    """Liveness probe response."""
    status: str = Field(default="alive")


class ReadinessResponse(BaseModel):
    """Readiness probe response."""
    status: str = Field(..., description="ready or not_ready")
    checks: dict[str, str] = Field(default_factory=dict)


@router.get(
    "",
    response_model=SimpleHealthResponse,
    summary="Simple Health Check",
    description="Quick health check for load balancers and monitoring.",
)
async def health_check() -> SimpleHealthResponse:
    """
    Simple health check endpoint.

    Returns basic status information for load balancers
    and external monitoring systems.
    """
    return SimpleHealthResponse(
        status="healthy",
        timestamp=datetime.now(timezone.utc),
        version=settings.app_version,
    )


@router.get(
    "/detailed",
    response_model=HealthResponse,
    summary="Detailed Health Check",
    description="Comprehensive health check including all system components.",
)
async def detailed_health_check() -> HealthResponse:
    """
    Detailed health check endpoint.

    Returns comprehensive status information including
    the health of all system components.
    """
    components: dict[str, ComponentStatus] = {}

    database_available = False
    database_tables: dict[str, bool] = {}

    # Database status
    if settings.db_enabled:
        try:
            from app.database import get_database
            db = get_database()
            health = await db.health_check()
            database_available = health.get("connected") is True
            if database_available:
                components["database"] = ComponentStatus(
                    name="PostgreSQL Database",
                    status="online",
                    message="Connected",
                )
            else:
                components["database"] = ComponentStatus(
                    name="PostgreSQL Database",
                    status="offline",
                    message="Not initialized",
                )
            if database_available:
                tables = await db.execute_one("""
                    SELECT
                        to_regclass('public.events') IS NOT NULL AS events,
                        to_regclass('public.alerts') IS NOT NULL AS alerts,
                        to_regclass('public.incidents') IS NOT NULL AS incidents
                """)
                database_tables = dict(tables or {})
        except Exception as e:
            components["database"] = ComponentStatus(
                name="PostgreSQL Database",
                status="offline",
                message=str(e),
            )
    else:
        components["database"] = ComponentStatus(
            name="PostgreSQL Database",
            status="pending",
            message="Disabled (set DB_ENABLED=true to enable)",
        )

    # Redis status (pending)
    components["redis"] = ComponentStatus(
        name="Redis Cache",
        status="pending",
        message="Not configured",
    )

    # Detection Engine status
    try:
        from app.detection import get_detection_engine
        engine = get_detection_engine()
        stats = engine.get_statistics()
        components["detection"] = ComponentStatus(
            name="Detection Engine",
            status="online",
            message=f"{stats['rules']['total_rules']} rules, {stats['iocs']['total']} IOCs",
        )
    except Exception as e:
        components["detection"] = ComponentStatus(
            name="Detection Engine",
            status="offline",
            message=str(e),
        )

    # LLM status
    try:
        from app.llm import get_llm_client
        client = get_llm_client()
        if client.is_available:
            components["ai"] = ComponentStatus(
                name="AI Analyst (LLM)",
                status="online",
                message=f"Model: {settings.llm_model}",
            )
        else:
            components["ai"] = ComponentStatus(
                name="AI Analyst (LLM)",
                status="degraded",
                message="Running in mock mode (no API key)",
            )
    except Exception as e:
        components["ai"] = ComponentStatus(
            name="AI Analyst (LLM)",
            status="offline",
            message=str(e),
        )

    # Agent status reflects successful execution and required dependencies,
    # not merely whether importing the dispatcher succeeded.
    try:
        from app.agents.dispatcher import get_dispatcher
        from app.agents.base import AgentType
        dispatcher = get_dispatcher()
        agent_components = {
            AgentType.EMAIL: ("email_agent", "Email Security Agent", True, "Email analysis agent"),
            AgentType.LOG: ("log_agent", "Log Analyzer Agent", True, "Log analysis agent"),
            AgentType.NETWORK: ("network_agent", "Network Analysis Agent", True, "Network analysis agent"),
        }
        for agent_type, (key, name, available, description) in agent_components.items():
            _add_agent_component(components, dispatcher, agent_type, key, name, available, description)

        try:
            from app.services.threat_intel.service import get_threat_intel_service
            ti_service = get_threat_intel_service()
            _add_agent_component(
                components, dispatcher, AgentType.THREAT_INTEL,
                "threat_intel_agent", "Threat Intelligence Agent",
                ti_service.is_configured,
                "Threat-intelligence provider configured" if ti_service.is_configured else "No threat-intelligence provider configured",
            )
        except Exception:
            _add_agent_component(
                components, dispatcher, AgentType.THREAT_INTEL,
                "threat_intel_agent", "Threat Intelligence Agent", False,
                "Threat-intelligence service unavailable",
            )

        _add_agent_component(
            components, dispatcher, AgentType.IOC_CORRELATION,
            "ioc_correlation_agent", "IOC Correlation Agent",
            database_available,
            "Requires the PostgreSQL finding/correlation store",
        )
        _add_agent_component(
            components, dispatcher, AgentType.INCIDENT_RESPONSE,
            "incident_response_agent", "Incident Response Agent",
            database_available and database_tables.get("incidents", False),
            "Requires the migrated incidents table",
        )
        _add_agent_component(
            components, dispatcher, AgentType.REPORTING,
            "reporting_agent", "Reporting Agent",
            database_available and database_tables.get("events", False) and database_tables.get("alerts", False),
            "Requires persisted events and alerts",
        )
    except Exception as e:
        components["email_agent"] = ComponentStatus(
            name="Email Security Agent",
            status="offline",
            message=str(e),
        )
        components["log_agent"] = ComponentStatus(
            name="Log Analyzer Agent",
            status="offline",
            message=str(e),
        )
        components["network_agent"] = ComponentStatus(
            name="Network Analysis Agent",
            status="offline",
            message=str(e),
        )

    # Determine overall status
    statuses = [c.status for c in components.values()]
    online_count = sum(1 for s in statuses if s == "online")

    if online_count >= 5:  # Most core components online
        overall_status = "healthy"
    elif any(s == "offline" for s in statuses):
        overall_status = "degraded"
    else:
        overall_status = "degraded"

    return HealthResponse(
        status=overall_status,
        timestamp=datetime.now(timezone.utc),
        version=settings.app_version,
        environment=settings.environment,
        components=components,
    )


def _add_agent_component(
    components: dict[str, ComponentStatus],
    dispatcher,
    agent_type,
    key: str,
    name: str,
    dependency_available: bool,
    dependency_message: str,
) -> None:
    agent = dispatcher.get_agent(agent_type)
    stats = agent.stats if agent is not None else {}
    if agent is None or agent.__class__.__name__ == "PlaceholderAgent":
        status = "offline"
        message = "Agent implementation is not registered"
    elif not dependency_available:
        status = "offline" if agent_type.value != "threat_intel" else "pending"
        message = dependency_message
    elif stats.get("status") == "error":
        status = "degraded"
        message = "Last execution failed; inspect backend logs"
    elif not stats.get("last_successful_run"):
        status = "pending"
        message = f"Registered; awaiting a successful execution. {dependency_message}"
    else:
        status = "online"
        message = dependency_message

    components[key] = ComponentStatus(
        name=name,
        status=status,
        message=message,
        last_run=stats.get("last_run"),
        last_successful_run=stats.get("last_successful_run"),
        total_analyzed=stats.get("total_analyzed"),
        error_count=stats.get("error_count"),
    )


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    summary="Readiness Probe",
    description="Check if the service is ready to accept traffic.",
)
async def readiness_check(response: Response) -> ReadinessResponse:
    """
    Readiness probe for Kubernetes/load balancers.

    Checks if critical infrastructure is available.
    Returns 503 if not ready to accept traffic.
    """
    checks = {}
    is_ready = True

    # Check Redis
    try:
        from app.cache import get_redis_client
        redis_client = await get_redis_client()
        health = await redis_client.health_check()
        if health.get("status") == "healthy":
            checks["redis"] = "ok"
        else:
            checks["redis"] = "unavailable"
            # Redis unavailable is degraded but not fatal
    except Exception:
        checks["redis"] = "unavailable"

    # Check ML model
    try:
        from app.ml.classifier import get_model_status
        ml_status = get_model_status()
        if ml_status.get("loaded"):
            checks["ml_model"] = "ok"
        else:
            checks["ml_model"] = "not_loaded"
    except Exception:
        checks["ml_model"] = "unavailable"

    # Check agents
    try:
        from app.agents.dispatcher import get_dispatcher
        get_dispatcher()
        checks["agents"] = "ok"
    except Exception:
        checks["agents"] = "unavailable"
        is_ready = False

    if is_ready:
        return ReadinessResponse(status="ready", checks=checks)
    else:
        response.status_code = 503
        return ReadinessResponse(status="not_ready", checks=checks)


@router.get(
    "/live",
    response_model=LivenessResponse,
    summary="Liveness Probe",
    description="Check if the service is alive. Does not depend on external services.",
)
async def liveness_check() -> LivenessResponse:
    """
    Liveness probe for Kubernetes.

    Only checks if the process is alive.
    Does NOT check external dependencies.
    """
    return LivenessResponse(status="alive")
