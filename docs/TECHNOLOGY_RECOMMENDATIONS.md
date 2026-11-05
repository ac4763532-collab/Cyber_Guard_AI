# CyberGuard AI - Professional Technology Recommendations

## Executive Summary

This document outlines recommended technologies to elevate CyberGuard AI to production-grade, professional-level cybersecurity platform suitable for enterprise deployment.

---

## 🏗️ Current Architecture vs Recommended

| Component | Current | Recommended | Priority |
|-----------|---------|-------------|----------|
| Auth | Firebase + Custom JWT | **Firebase + Auth0/Keycloak** | HIGH |
| Database | PostgreSQL | PostgreSQL + **TimescaleDB** | HIGH |
| Cache | None | **Redis + Valkey** | HIGH |
| Queue | None | **Celery + Redis** or **BullMQ** | HIGH |
| Search | None | **Elasticsearch/OpenSearch** | MEDIUM |
| Vectors | None | **Pinecone/Weaviate/pgvector** | HIGH |
| Monitoring | Structlog | **OpenTelemetry + Grafana** | HIGH |
| CI/CD | None | **GitHub Actions + Docker** | HIGH |
| API Gateway | None | **Kong/Traefik** | MEDIUM |
| Secrets | .env files | **HashiCorp Vault** | HIGH |

---

## 1. 🔐 Authentication & Authorization

### Current State
- Firebase Auth (Google, Email, Phone)
- Custom JWT tokens
- Basic RBAC

### Recommended Enhancements

#### Option A: Enhanced Firebase (Simpler)
```
Firebase Auth
    ↓
Firebase Custom Claims (roles/permissions)
    ↓
Backend verifies + ABAC (Attribute-Based Access Control)
```

#### Option B: Enterprise-Grade (More Control)
```
┌──────────────────────────────────────────────────┐
│                   Keycloak / Auth0               │
│  - SSO (SAML, OIDC)                             │
│  - Multi-factor Authentication                   │
│  - Fine-grained Permissions                      │
│  - User Federation (LDAP/AD)                     │
│  - Audit Logging                                 │
└──────────────────────────────────────────────────┘
```

### Implementation
```bash
# For Auth0 (SaaS - easier)
pip install authlib python-jose

# For Keycloak (Self-hosted - more control)
docker run -p 8080:8080 quay.io/keycloak/keycloak start-dev
```

---

## 2. 📊 Database & Storage

### Current State
- PostgreSQL (disabled)
- In-memory storage

### Recommended: TimescaleDB + PostgreSQL

**Why TimescaleDB?**
- Native time-series support for security events
- Automatic partitioning (hypertables)
- 10-100x faster queries on time-series data
- Compression (90%+ storage reduction)
- Compatible with PostgreSQL ecosystem

```sql
-- Convert events table to hypertable
SELECT create_hypertable('events', 'created_at');

-- Add compression policy (compress data older than 7 days)
ALTER TABLE events SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'event_type, source'
);
SELECT add_compression_policy('events', INTERVAL '7 days');

-- Continuous aggregates for dashboards
CREATE MATERIALIZED VIEW hourly_event_stats
WITH (timescaledb.continuous) AS
SELECT time_bucket('1 hour', created_at) AS bucket,
       event_type,
       count(*) as event_count,
       avg(risk_score) as avg_risk
FROM events
GROUP BY bucket, event_type;
```

### Setup
```bash
# Docker
docker run -d --name timescaledb \
    -p 5432:5432 \
    -e POSTGRES_PASSWORD=password \
    timescale/timescaledb:latest-pg16

# Or install extension on existing PostgreSQL
CREATE EXTENSION IF NOT EXISTS timescaledb;
```

---

## 3. 🚀 Caching Layer (Redis)

### Why Redis?
- Session storage
- Rate limiting
- Real-time pub/sub for WebSocket
- API response caching
- Distributed locks

```python
# backend/app/cache/redis_client.py
import redis.asyncio as redis
from app.config import get_settings

class RedisClient:
    def __init__(self):
        settings = get_settings()
        self.client = redis.from_url(settings.redis_url)
    
    async def cache_detection(self, hash: str, result: dict, ttl: int = 3600):
        """Cache detection result to avoid re-processing identical data."""
        await self.client.setex(f"detection:{hash}", ttl, json.dumps(result))
    
    async def get_cached_detection(self, hash: str) -> dict | None:
        """Get cached detection result."""
        data = await self.client.get(f"detection:{hash}")
        return json.loads(data) if data else None
    
    async def rate_limit(self, key: str, limit: int, window: int) -> bool:
        """Check rate limit. Returns True if allowed."""
        current = await self.client.incr(key)
        if current == 1:
            await self.client.expire(key, window)
        return current <= limit
```

---

## 4. 📨 Task Queue (Celery/BullMQ)

### Why Task Queue?
- Async processing of heavy analysis
- Scheduled threat intelligence updates
- Email notifications
- Report generation
- Retry logic for failed tasks

### Celery Setup
```python
# backend/app/tasks/celery_app.py
from celery import Celery
from app.config import get_settings

settings = get_settings()

celery_app = Celery(
    "cyberguard",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300,  # 5 minutes
)


# backend/app/tasks/analysis.py
from app.tasks.celery_app import celery_app
from app.llm import get_llm_client

@celery_app.task(bind=True, max_retries=3)
def analyze_threat_async(self, findings: list, context: dict = None):
    """Run AI threat analysis as background task."""
    try:
        client = get_llm_client()
        # ... async analysis
        return result.dict()
    except Exception as exc:
        self.retry(exc=exc, countdown=60)
```

---

## 5. 🔍 Vector Database for RAG

### Why Vector Database?
- Semantic search over MITRE ATT&CK
- Similar incident retrieval
- Knowledge base queries
- Contextual AI responses

### Recommended: pgvector (PostgreSQL extension)

**Advantages:**
- No new infrastructure
- Works with existing PostgreSQL
- Cost-effective
- Good enough for 1M+ vectors

```sql
-- Enable pgvector
CREATE EXTENSION vector;

-- Knowledge base table with embeddings
CREATE TABLE knowledge_embeddings (
    id SERIAL PRIMARY KEY,
    content TEXT NOT NULL,
    embedding vector(1536),  -- OpenAI ada-002 dimension
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create HNSW index for fast similarity search
CREATE INDEX ON knowledge_embeddings 
USING hnsw (embedding vector_cosine_ops);

-- Similarity search
SELECT content, metadata, 
       1 - (embedding <=> $1) as similarity
FROM knowledge_embeddings
ORDER BY embedding <=> $1
LIMIT 10;
```

### Alternative: Pinecone (SaaS)
```python
import pinecone

pinecone.init(api_key="xxx", environment="us-west1-gcp")
index = pinecone.Index("cyberguard-knowledge")

# Upsert vectors
index.upsert(vectors=[
    {"id": "mitre-t1566", "values": embedding, "metadata": {"technique": "Phishing"}}
])

# Query
results = index.query(vector=query_embedding, top_k=10, include_metadata=True)
```

---

## 6. 📈 Observability Stack

### OpenTelemetry + Grafana Stack

```
┌─────────────────────────────────────────────────────────────┐
│                    Grafana Dashboard                         │
└─────────────────────────────────────────────────────────────┘
                              ↑
        ┌─────────────────────┼─────────────────────┐
        ↓                     ↓                     ↓
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│    Loki       │    │   Prometheus  │    │    Tempo      │
│   (Logs)      │    │  (Metrics)    │    │  (Traces)     │
└───────────────┘    └───────────────┘    └───────────────┘
        ↑                     ↑                     ↑
        └─────────────────────┼─────────────────────┘
                              ↑
                    ┌─────────────────┐
                    │  OpenTelemetry  │
                    │   Collector     │
                    └─────────────────┘
                              ↑
                    ┌─────────────────┐
                    │  CyberGuard AI  │
                    │    Backend      │
                    └─────────────────┘
```

### FastAPI Integration
```python
# backend/app/observability/tracing.py
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

def setup_tracing(app):
    """Setup distributed tracing."""
    provider = TracerProvider()
    processor = BatchSpanProcessor(OTLPSpanExporter())
    provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)
    
    FastAPIInstrumentor.instrument_app(app)
```

---

## 7. 🐳 Containerization & Deployment

### Docker Compose (Development)
```yaml
# docker-compose.yml
version: '3.8'

services:
  backend:
    build: ./backend
    ports:
      - "8000:8000"
    environment:
      - DB_ENABLED=true
      - DB_HOST=timescaledb
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - timescaledb
      - redis

  frontend:
    build: ./frontend
    ports:
      - "3000:80"
    depends_on:
      - backend

  timescaledb:
    image: timescale/timescaledb:latest-pg16
    volumes:
      - pgdata:/var/lib/postgresql/data
    environment:
      - POSTGRES_DB=cyberguard
      - POSTGRES_PASSWORD=${DB_PASSWORD}

  redis:
    image: redis:7-alpine
    volumes:
      - redisdata:/data

  celery:
    build: ./backend
    command: celery -A app.tasks.celery_app worker --loglevel=info
    depends_on:
      - redis
      - timescaledb

volumes:
  pgdata:
  redisdata:
```

### Kubernetes (Production)
```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cyberguard-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: cyberguard-backend
  template:
    spec:
      containers:
      - name: backend
        image: cyberguard/backend:latest
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /api/v1/health
            port: 8000
        env:
          - name: ANTHROPIC_API_KEY
            valueFrom:
              secretKeyRef:
                name: cyberguard-secrets
                key: anthropic-api-key
```

---

## 8. 🔒 Secrets Management

### HashiCorp Vault
```python
# backend/app/config/vault.py
import hvac

class VaultClient:
    def __init__(self, url: str, token: str):
        self.client = hvac.Client(url=url, token=token)
    
    def get_secret(self, path: str) -> dict:
        """Get secret from Vault."""
        result = self.client.secrets.kv.v2.read_secret_version(path=path)
        return result['data']['data']

# Usage
vault = VaultClient(url="https://vault.example.com", token=os.environ["VAULT_TOKEN"])
secrets = vault.get_secret("cyberguard/production")
anthropic_key = secrets["anthropic_api_key"]
```

---

## 9. 🧪 Testing Strategy

### Test Pyramid
```
              ┌─────────────────┐
              │   E2E Tests     │  (Playwright)
              │   5-10 tests    │
              └────────┬────────┘
                       │
         ┌─────────────┴─────────────┐
         │    Integration Tests      │  (pytest + testcontainers)
         │       50-100 tests        │
         └─────────────┬─────────────┘
                       │
    ┌──────────────────┴──────────────────┐
    │           Unit Tests                 │  (pytest)
    │          200-500 tests               │
    └──────────────────────────────────────┘
```

### Testing Tools
```bash
# Backend
pip install pytest pytest-asyncio pytest-cov testcontainers httpx

# Frontend
npm install -D vitest @testing-library/react playwright
```

### Example Tests
```python
# backend/tests/test_detection.py
import pytest
from httpx import AsyncClient
from app.main import app

@pytest.mark.asyncio
async def test_detection_endpoint():
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.post("/api/v1/detection/analyze", json={
            "data": {"source_ip": "192.168.1.100", "event": "login_failed"}
        })
        assert response.status_code == 200
        assert "risk_score" in response.json()
```

---

## 10. 📋 Recommended Implementation Roadmap

### Phase 1: Foundation (Week 1-2)
- [x] Firebase Authentication
- [x] PostgreSQL Database
- [x] Enhanced LLM Client
- [ ] Redis Caching
- [ ] Docker Compose setup

### Phase 2: Core Features (Week 3-4)
- [ ] Celery task queue
- [ ] TimescaleDB migration
- [ ] OpenTelemetry tracing
- [ ] Rate limiting

### Phase 3: Intelligence (Week 5-6)
- [ ] pgvector for RAG
- [ ] MITRE ATT&CK embedding search
- [ ] Threat intelligence feeds
- [ ] Similar incident retrieval

### Phase 4: Production (Week 7-8)
- [ ] Kubernetes manifests
- [ ] Vault secrets management
- [ ] CI/CD pipeline
- [ ] Load testing

---

## 📦 Updated Requirements

```txt
# backend/requirements.txt additions

# Caching & Queue
redis>=5.0.0
celery>=5.3.0

# Vector Database
pgvector>=0.2.0

# Observability
opentelemetry-api>=1.20.0
opentelemetry-sdk>=1.20.0
opentelemetry-instrumentation-fastapi>=0.41b0
opentelemetry-exporter-otlp>=1.20.0

# Testing
pytest>=8.0.0
pytest-asyncio>=0.23.0
pytest-cov>=4.1.0
httpx>=0.27.0
testcontainers>=3.7.0

# Security
python-jose[cryptography]>=3.3.0
passlib[bcrypt]>=1.7.4
```

---

## Summary

These technologies will transform CyberGuard AI from a proof-of-concept into a **production-ready, enterprise-grade** cybersecurity platform:

| Technology | Impact |
|------------|--------|
| TimescaleDB | 10-100x faster event queries |
| Redis | Sub-millisecond caching |
| Celery | Async processing at scale |
| pgvector | Semantic search for intelligence |
| OpenTelemetry | Full observability |
| Docker/K8s | Production deployment |
| Vault | Enterprise secrets management |

**Most Important for Final Year Project:**
1. ✅ Redis (immediate impact, easy to add)
2. ✅ Docker Compose (professional deployment)
3. ✅ OpenTelemetry (shows observability knowledge)
4. ✅ pgvector (demonstrates RAG/AI knowledge)
