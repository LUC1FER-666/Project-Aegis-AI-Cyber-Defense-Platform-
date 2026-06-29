"""
Aegis AI — Asset Discovery Service
Discovers, inventories, and tracks all assets in the environment.
"""
from __future__ import annotations
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from prometheus_fastapi_instrumentator import Instrumentator

import sys
sys.path.insert(0, "/shared/python")
from aegis_common.logging import configure_logging, get_logger
from aegis_common.models import HealthResponse

from app.config import get_settings
from app.database import engine, AsyncSessionLocal
from app.models.db import Base
from app.routers.assets import router as assets_router
from app.kafka_client import close_producer

settings = get_settings()
configure_logging(settings.service_name, settings.log_level, settings.environment)
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logger.info("asset_discovery_starting")

    # Create DB tables
    async with engine.begin() as conn:
        await conn.execute(text("CREATE SCHEMA IF NOT EXISTS assets"))
        await conn.run_sync(Base.metadata.create_all)
    logger.info("database_ready")

    yield

    await close_producer()
    await engine.dispose()
    logger.info("asset_discovery_stopped")


app = FastAPI(
    title="Aegis AI — Asset Discovery",
    version="0.1.0",
    docs_url="/docs",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Instrumentator().instrument(app).expose(app, endpoint="/metrics")

app.include_router(assets_router, prefix="/api/v1")


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    checks: dict[str, str] = {}
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["postgres"] = "ok"
    except Exception as e:
        checks["postgres"] = f"error: {e}"

    return HealthResponse(
        status="healthy" if all(v == "ok" for v in checks.values()) else "degraded",
        service=settings.service_name,
        version="0.1.0",
        environment=settings.environment,
        checks=checks,
    )


@app.get("/")
async def root() -> dict:
    return {"service": "Aegis AI Asset Discovery", "version": "0.1.0"}
