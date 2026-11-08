# ============================================================================
# CyberGuard AI — Backend Dockerfile
# ============================================================================
# 
# Builds a slim, secure production image for the FastAPI backend.
#
# Key Design Decisions:
#   - Python 3.12-slim: Alpine is too small (compilation issues), Buster is too big.
#   - Non-root user: If the container is compromised, the attacker doesn't get root.
#   - Healthcheck: Docker will automatically restart the container if /health fails.
#   - Build caching: requirements.txt is copied and installed BEFORE the code,
#     so code changes don't trigger a full pip re-install.
# ============================================================================

FROM python:3.12-slim

# Environment variables
# PYTHONDONTWRITEBYTECODE: Prevents Python from writing .pyc files (keeps image small)
# PYTHONUNBUFFERED: Ensures logs are printed immediately to stdout (crucial for Docker logs)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install system dependencies
# gcc + libpq-dev: Needed to compile psycopg2 (PostgreSQL driver) and other C-extensions
# curl: Needed for the HEALTHCHECK command
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
# Copied separately to leverage Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Create a non-root user and change ownership of the app directory
RUN adduser --disabled-password --gecos "" appuser && \
    chown -R appuser:appuser /app
USER appuser

# Expose the FastAPI port
EXPOSE 8000

# Healthcheck (uses the /health endpoint we built in File 140)
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Start Uvicorn
# --workers 4: Good default for a 2-core VM. For production, set this via environment.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]