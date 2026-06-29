"""
Aegis AI — Threat Defense Agent (port 8006)
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import kafka
from app.api.routes import router
from app.config import get_settings
from app.database import create_tables

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

_monitor_task: asyncio.Task | None = None


async def _background_monitor() -> None:
    """Poll detection engine every 30s and run the defense agent."""
    settings = get_settings()
    while True:
        try:
            await asyncio.sleep(settings.monitor_interval_seconds)
            logger.info("Background monitor: running defense agent cycle")
            from app.api.routes import run_agent
            from app.database import _get_session_factory
            factory = _get_session_factory()
            async with factory() as db:
                await run_agent(db)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("Background monitor error: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _monitor_task
    settings = get_settings()

    try:
        await create_tables()
        logger.info("Database tables created/verified")
    except Exception as exc:
        logger.warning("DB init failed (%s) — continuing without DB", exc)

    await kafka.init_kafka(settings.kafka_bootstrap_servers)

    _monitor_task = asyncio.create_task(_background_monitor())

    yield

    if _monitor_task and not _monitor_task.done():
        _monitor_task.cancel()
        try:
            await _monitor_task
        except asyncio.CancelledError:
            pass

    await kafka.close_kafka()
    logger.info("Threat Defense Agent shut down cleanly")


app = FastAPI(
    title="Aegis AI — Threat Defense Agent",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, tags=["threat-defense-agent"])


@app.get("/")
async def root():
    return {"service": "threat-defense-agent", "version": "1.0.0", "docs": "/docs"}
