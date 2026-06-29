"""
Aegis AI — Milestone 7: Live Attack Timeline + Interactive Attack Graph
Service runs on port 8007.
"""
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import engine, Base
from app.core.redis_client import redis_client
from app.core.neo4j_client import neo4j_client
from app.api import timeline, graph
from app.services.timeline_collector import TimelineCollector
from app.services.graph_builder import GraphBuilder

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    # Create PostgreSQL tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("PostgreSQL tables ready")

    # Connect Redis
    await redis_client.connect()
    logger.info("Redis connected")

    # Connect Neo4j (optional — graceful if unavailable)
    await neo4j_client.connect()
    logger.info("Neo4j connection attempted")

    # Start background tasks
    collector = TimelineCollector()
    builder = GraphBuilder()

    collector_task = asyncio.create_task(collector.run_forever())
    builder_task = asyncio.create_task(builder.run_forever())

    app.state.collector = collector
    app.state.builder = builder

    yield

    # Shutdown
    collector_task.cancel()
    builder_task.cancel()
    await asyncio.gather(collector_task, builder_task, return_exceptions=True)
    await redis_client.disconnect()
    await neo4j_client.disconnect()
    await engine.dispose()
    logger.info("Timeline + Graph service shut down")


app = FastAPI(
    title="Aegis AI — Timeline + Graph Service",
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

app.include_router(timeline.router, prefix="/api/v1/timeline", tags=["timeline"])
app.include_router(graph.router, prefix="/api/v1/graph", tags=["graph"])


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "timeline-graph",
        "neo4j_connected": neo4j_client.is_connected,
        "redis_connected": redis_client.is_connected,
    }
