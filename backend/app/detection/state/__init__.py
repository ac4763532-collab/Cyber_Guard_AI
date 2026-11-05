"""
CyberGuard AI - Detection State Management

STEP 8.2.1: Redis-backed state for production detection rules.

Exports:
- DetectionStateManager: Main interface for windowed event tracking
- RedisUnavailableError: Raised when Redis is down (fail loudly)
- get_detection_state_manager: Factory function
"""

from app.detection.state.redis_state import (
    DetectionStateManager,
    RedisUnavailableError,
    get_detection_state_manager,
    close_detection_state,
)

__all__ = [
    "DetectionStateManager",
    "RedisUnavailableError",
    "get_detection_state_manager",
    "close_detection_state",
]
