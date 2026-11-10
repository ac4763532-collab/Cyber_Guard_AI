# ============================================================================
# CyberGuard AI — Hugging Face Spaces Production Dockerfile
# ============================================================================
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/backend \
    PORT=7860

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r ./backend/requirements.txt && \
    pip install --no-cache-dir joblib huggingface_hub

# Copy application code
COPY backend ./backend

# Create a non-root user (UID 1000 required by Hugging Face Spaces)
RUN useradd -m -u 1000 user && \
    chown -R user:user /app
USER user

WORKDIR /app/backend

# Hugging Face Spaces listens on port 7860
EXPOSE 7860

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "7860"]
