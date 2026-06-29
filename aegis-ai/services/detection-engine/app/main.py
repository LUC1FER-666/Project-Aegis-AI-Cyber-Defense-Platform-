"""
Detection Engine — Main Application
Port 8004

Startup sequence:
1. Create DB tables (Alembic in production; create_all for dev convenience)
2. Load Sigma rules from disk
3. Start Kafka consumer + publisher
4. Begin serving API requests
"""
import logging

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import engine
from app.models import Base
from app.engines.sigma_engine import SigmaRuleEngine
from app.engines.ml_engine import MLAnomalyDetector
from app.engines.llm_engine import LLMReasoningEngine
from app.engines.correlator import AlertCorrelator
from app.pipeline import DetectionPipeline
from app.kafka import KafkaPublisher, TelemetryConsumer
from app.api.routes import router, set_pipeline

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Global instances (set during lifespan)
_consumer: TelemetryConsumer | None = None
_publisher: KafkaPublisher | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _consumer, _publisher

    # ── DB tables ──────────────────────────────────────────────────────────────
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables ready")

    # ── Sigma rules ────────────────────────────────────────────────────────────
    sigma = SigmaRuleEngine(rules_path=settings.sigma_rules_path)
    n_rules = sigma.load_rules()
    logger.info("Loaded %d Sigma rules", n_rules)

    # ── ML detector ────────────────────────────────────────────────────────────
    ml = MLAnomalyDetector(
        min_samples=settings.anomaly_min_samples,
        contamination=settings.anomaly_contamination,
        retrain_interval=settings.anomaly_retrain_interval,
    )

    # ── LLM engine ─────────────────────────────────────────────────────────────
    llm = LLMReasoningEngine(
        ollama_base_url=settings.ollama_base_url,
        model=settings.ollama_model,
        enabled=settings.llm_enabled,
    )

    # ── Correlator ─────────────────────────────────────────────────────────────
    correlator = AlertCorrelator(
        window_seconds=settings.correlation_window_seconds,
        min_alerts=settings.correlation_min_alerts,
    )

    # ── Publisher ──────────────────────────────────────────────────────────────
    _publisher = KafkaPublisher(bootstrap_servers=settings.kafka_bootstrap_servers)
    await _publisher.start()

    # ── Pipeline ───────────────────────────────────────────────────────────────
    pipeline = DetectionPipeline(
        sigma_engine=sigma,
        ml_detector=ml,
        llm_engine=llm,
        correlator=correlator,
        kafka_publisher=_publisher,
    )
    set_pipeline(pipeline)

    # ── Consumer ───────────────────────────────────────────────────────────────
    _consumer = TelemetryConsumer(pipeline=pipeline, publisher=_publisher)
    await _consumer.start()

    logger.info("Detection Engine ready on port %d", settings.service_port)

    yield  # ── serve ──────────────────────────────────────────────────────────

    # Teardown
    if _consumer:
        await _consumer.stop()
    if _publisher:
        await _publisher.stop()
    await engine.dispose()
    logger.info("Detection Engine shut down cleanly")


app = FastAPI(
    title="Aegis AI — Detection Engine",
    version="1.0.0",
    description="4-layer autonomous cyber threat detection: Sigma + ML + LLM + Correlation",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")


# Root redirect
@app.get("/")
async def root():
    return {"service": "detection-engine", "version": "1.0.0", "port": 8004}
