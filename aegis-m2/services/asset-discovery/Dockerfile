FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app:/shared/python

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl nmap \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir \
    fastapi "uvicorn[standard]" "sqlalchemy[asyncio]" asyncpg \
    "python-jose[cryptography]" bcrypt \
    "pydantic[email]" pydantic-settings \
    aiokafka structlog httpx \
    python-nmap netaddr \
    "redis[hiredis]" \
    prometheus-client prometheus-fastapi-instrumentator

COPY . .

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

EXPOSE 8001
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
