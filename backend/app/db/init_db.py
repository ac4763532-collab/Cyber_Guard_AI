"""
CyberGuard AI — Database Initialization & Table Generation
============================================================================
Ensures all 32 domain tables and indexes are created in PostgreSQL.
"""

from __future__ import annotations

import logging
from app.db.base import Base
from app.db.session import engine, session_scope
import app.models  # registers all 32 models

logger = logging.getLogger(__name__)


def init_db() -> None:
    """Create all tables defined in Base.metadata if they do not exist."""
    logger.info("Initializing database schema...")
    try:
        Base.metadata.create_all(bind=engine)
        logger.info(f"Database schema initialized successfully! Total tables: {len(Base.metadata.tables)}")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise


if __name__ == "__main__":
    init_db()
