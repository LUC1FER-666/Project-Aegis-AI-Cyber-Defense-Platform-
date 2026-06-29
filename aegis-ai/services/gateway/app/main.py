"""
Aegis AI — Gateway Service
Entry point. FastAPI app factory with middleware, lifespan, and route registration.
"""
from __future__ import annotations

import time
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

import redis.asyncio as aioredis
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator
from sqlalchemy import text

import sys
sys.path.insert(0, "/shared/python")
from aegis_common.logging import configure_logging, get_logger
from aegis_common.models import HealthResponse

from app.config import get_settings
from app.database import engine
from app.models.db import Base
from app.routers import auth, users
from app.services.startup import create_initial_admin

settings = get_settings()
configure_logging(settings.service_name, settings.log_level, settings.environment)
logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Lifespan — startup and shutdown logic
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Runs on startup and shutdown.
    Creates DB tables, seeds initial admin, warms up connections.
    """
    logger.info("gateway_starting", environment=settings.environment)

    # Create tables (in production, use Alembic migrations instead)
    if settings.environment == "development":
        async with engine.begin() as conn:
            await conn.execute(text("CREATE SCHEMA IF NOT EXISTS auth"))
            await conn.execute(text("CREATE SCHEMA IF NOT EXISTS audit"))
            await conn.run_sync(Base.metadata.create_all)
        logger.info("database_tables_created")

    # Create initial admin user if not exists
    await create_initial_admin(settings)
    logger.info("gateway_ready", port=settings.service_port)

    yield

    # Shutdown
    await engine.dispose()
    logger.info("gateway_stopped")


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    app = FastAPI(
        title="Aegis AI — Gateway",
        description="Authentication, authorization, and routing for the Aegis AI platform",
        version="0.1.0",
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        openapi_url="/openapi.json" if not settings.is_production else None,
        lifespan=lifespan,
    )

    # ---- Middleware ----

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next) -> Response:
        """Add X-Request-ID header to every response for tracing."""
        import uuid
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        start_time = time.monotonic()
        response = await call_next(request)
        duration_ms = round((time.monotonic() - start_time) * 1000, 2)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-Ms"] = str(duration_ms)
        logger.debug(
            "http_request",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=duration_ms,
            request_id=request_id,
        )
        return response

    # ---- Prometheus metrics ----
    Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        excluded_handlers=["/health", "/metrics"],
    ).instrument(app).expose(app, endpoint="/metrics")

    # ---- Routes ----
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(users.router, prefix="/api/v1")

    # ---- Health check ----
    @app.get("/health", response_model=HealthResponse, tags=["Platform"])
    async def health() -> HealthResponse:
        """
        Service health check. Used by Docker, Kubernetes, and load balancers.
        Checks connectivity to all dependencies.
        """
        checks: dict[str, str] = {}

        # PostgreSQL
        try:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            checks["postgres"] = "ok"
        except Exception as e:
            checks["postgres"] = f"error: {e}"

        # Redis
        try:
            redis = await aioredis.from_url(settings.redis_url)
            await redis.ping()
            await redis.aclose()
            checks["redis"] = "ok"
        except Exception as e:
            checks["redis"] = f"error: {e}"

        all_ok = all(v == "ok" for v in checks.values())

        return HealthResponse(
            status="healthy" if all_ok else "degraded",
            service=settings.service_name,
            version="0.1.0",
            environment=settings.environment,
            checks=checks,
        )

    @app.get("/", tags=["Platform"])
    async def root() -> dict:
        return {
            "service": "Aegis AI Gateway",
            "version": "0.1.0",
            "docs": "/docs",
        }

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.service_port,
        reload=settings.environment == "development",
        log_config=None,  # We handle logging ourselves
    )
