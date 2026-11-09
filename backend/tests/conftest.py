"""
CyberGuard AI — Test Configuration & Fixtures
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, CheckConstraint
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import JSONB, ARRAY, INET, CIDR, MACADDR, UUID, TSVECTOR

# Compile PostgreSQL-specific dialect types for SQLite compatibility in tests
@compiles(JSONB, "sqlite")
def compile_jsonb_sqlite(type_, compiler, **kw):
    return "JSON"

@compiles(ARRAY, "sqlite")
def compile_array_sqlite(type_, compiler, **kw):
    return "TEXT"

@compiles(INET, "sqlite")
def compile_inet_sqlite(type_, compiler, **kw):
    return "TEXT"

@compiles(CIDR, "sqlite")
def compile_cidr_sqlite(type_, compiler, **kw):
    return "TEXT"

@compiles(MACADDR, "sqlite")
def compile_macaddr_sqlite(type_, compiler, **kw):
    return "TEXT"


@compiles(TSVECTOR, "sqlite")
def compile_tsvector_sqlite(type_, compiler, **kw):
    return "TEXT"
@compiles(UUID, "sqlite")
def compile_uuid_sqlite(type_, compiler, **kw):
    return "TEXT"

import os
os.environ["APP_ENV"] = "test"
os.environ["AGENT_EXECUTION_ENABLED"] = "false"
os.environ["FIREBASE_AUTH_ENABLED"] = "false"

from app.core.config import settings
settings.APP_ENV = "test"
settings.AGENT_EXECUTION_ENABLED = False
settings.FIREBASE_AUTH_ENABLED = False

import app.db.session
app.db.session.health_check = lambda: True

import app.main
from app.main import app
import sys; sys.modules["app.main"].health_check = lambda: True
from app.db.base import Base
from app.db.session import get_db

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    # Sanitize Postgres-specific CHECK constraints and server defaults for SQLite
    for table in Base.metadata.tables.values():
        table.constraints = {
            c for c in table.constraints 
            if not isinstance(c, CheckConstraint)
        }
        seen_names = set()
        unique_indexes = set()
        for idx in table.indexes:
            if idx.name not in seen_names:
                seen_names.add(idx.name)
                unique_indexes.add(idx)
        table.indexes = unique_indexes
        for col in table.columns:
            if hasattr(col, "computed") and col.computed is not None:
                col.computed = None
            if col.server_default is not None and hasattr(col.server_default, "arg"):
                txt = str(col.server_default.arg)
                if "::" in txt or "gen_random_uuid" in txt:
                    col.server_default = None

    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def db_session():
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()

@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
