"""
CyberGuard AI - Celery Task Queue Configuration
Background task processing for heavy analysis operations.
"""

from celery import Celery

from app.config import get_settings

settings = get_settings()

# Create Celery app
celery_app = Celery(
    "cyberguard",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "app.tasks.analysis",
        "app.tasks.notifications",
    ]
)

# Celery configuration
celery_app.conf.update(
    # Serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",

    # Timezone
    timezone="UTC",
    enable_utc=True,

    # Task tracking
    task_track_started=True,
    task_time_limit=300,  # 5 minutes hard limit
    task_soft_time_limit=240,  # 4 minutes soft limit (raises exception)

    # Result expiration
    result_expires=3600,  # 1 hour

    # Retry settings
    task_acks_late=True,
    task_reject_on_worker_lost=True,

    # Concurrency
    worker_prefetch_multiplier=1,  # One task at a time per worker

    # Beat schedule (for periodic tasks)
    beat_schedule={
        "update-threat-intelligence": {
            "task": "app.tasks.analysis.update_threat_intel",
            "schedule": 3600.0,  # Every hour
        },
        "cleanup-old-events": {
            "task": "app.tasks.analysis.cleanup_old_events",
            "schedule": 86400.0,  # Daily
        },
    },
)
