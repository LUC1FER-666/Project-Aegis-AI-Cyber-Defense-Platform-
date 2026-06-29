# =============================================================================
# AEGIS AI — Gateway Service Dockerfile
# Multi-stage build: build deps separately to keep final image small
# =============================================================================

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app:/shared/python

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
FROM base AS builder

RUN pip install --no-cache-dir uv

COPY pyproject.toml .
RUN uv pip install --system --no-cache -r pyproject.toml 2>/dev/null || \
    pip install --no-cache-dir \
        fastapi>=0.109.0 \
        "uvicorn[standard]>=0.27.0" \
        "sqlalchemy[asyncio]>=2.0.23" \
        asyncpg>=0.29.0 \
        alembic>=1.13.0 \
        "python-jose[cryptography]>=3.3.0" \
    
        pydantic>=2.5.0 \
        pydantic-settings>=2.1.0 \
        "redis[hiredis]>=5.0.1" \
        structlog>=24.1.0 \
        httpx>=0.26.0 \
        python-multipart>=0.0.7 \
        aiokafka>=0.10.0 \
        prometheus-client>=0.19.0 \
        prometheus-fastapi-instrumentator>=6.1.0 \
        bcrypt>=4.0.0

# ---------------------------------------------------------------------------
FROM base AS final

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY . .

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--log-config", "null"]
