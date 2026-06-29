"""
Aegis AI — Agent Orchestrator (port 8005)
"""
from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from typing import Any

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

_consumer_task: asyncio.Task | None = None


async def _incident_consumer() -> None:
    """
    Kafka consumer loop — reads from aegis.incidents.created and runs the pipeline.
    Runs without Kafka (logs warning and exits gracefully).
    """
    settings = get_settings()
    try:
        from aiokafka import AIOKafkaConsumer  # type: ignore

        consumer = AIOKafkaConsumer(
            "aegis.incidents.created",
            bootstrap_servers=settings.kafka_bootstrap_servers,
            group_id="agent-orchestrator-group",
            auto_offset_reset="latest",
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        )
        await consumer.start()
        logger.info("Kafka consumer started on aegis.incidents.created")

        async for msg in consumer:
            try:
                incident: dict[str, Any] = msg.value
                logger.info(
                    "Received incident from Kafka: id=%s severity=%s",
                    incident.get("id"),
                    incident.get("severity"),
                )
                from app.api.routes import _run_and_store
                from app.database import _get_session_factory

                factory = _get_session_factory()
                async with factory() as db:
                    await _run_and_store(incident, db)
            except Exception as exc:
                logger.error("Error processing Kafka incident message: %s", exc)

        await consumer.stop()
    except Exception as exc:
        logger.warning(
            "Kafka consumer failed to start (%s) — running without Kafka consumer.",
            exc,
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _consumer_task

    settings = get_settings()

    # Initialise DB
    try:
        await create_tables()
        logger.info("Database tables created/verified")
    except Exception as exc:
        logger.warning("DB init failed (%s) — will retry on first request", exc)

    # Initialise Kafka producer
    await kafka.init_kafka(settings.kafka_bootstrap_servers)

    # Start Kafka consumer in background
    _consumer_task = asyncio.create_task(_incident_consumer())

    yield

    # Shutdown
    if _consumer_task and not _consumer_task.done():
        _consumer_task.cancel()
        try:
            await _consumer_task
        except asyncio.CancelledError:
            pass

    await kafka.close_kafka()
    logger.info("Agent Orchestrator shut down cleanly")


app = FastAPI(
    title="Aegis AI — Agent Orchestrator",
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

app.include_router(router, tags=["agent-orchestrator"])


@app.get("/")
async def root():
    return {
        "service": "agent-orchestrator",
        "version": "1.0.0",
        "docs": "/docs",
    }
