"""
Kafka producer/consumer wrappers for Aegis services.
Handles serialization, error handling, and structured logging.

Usage (producer):
    async with AegisProducer(bootstrap_servers="localhost:9092") as producer:
        await producer.publish("aegis.detections.alerts", payload, source="detection-engine")

Usage (consumer):
    consumer = AegisConsumer(
        topics=["aegis.detections.alerts"],
        group_id="detection-processor",
        bootstrap_servers="localhost:9092",
    )
    async for message in consumer.stream():
        await handle(message)
"""
from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.errors import KafkaError

from aegis_common.logging import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Producer
# ---------------------------------------------------------------------------

class AegisProducer:
    """
    Async Kafka producer. Use as an async context manager.
    Wraps every message in the standard KafkaMessage envelope.
    """

    def __init__(self, bootstrap_servers: str | list[str]) -> None:
        servers = (
            bootstrap_servers
            if isinstance(bootstrap_servers, list)
            else [bootstrap_servers]
        )
        self._producer = AIOKafkaProducer(
            bootstrap_servers=servers,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
            key_serializer=lambda k: k.encode("utf-8") if k else None,
            compression_type="gzip",
            enable_idempotence=True,   # Exactly-once semantics on producer side
            acks="all",                # Wait for all replicas
            retry_backoff_ms=100,
            request_timeout_ms=30_000,
        )

    async def __aenter__(self) -> AegisProducer:
        await self._producer.start()
        logger.info("kafka_producer_started")
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self._producer.stop()
        logger.info("kafka_producer_stopped")

    async def publish(
        self,
        topic: str,
        payload: dict[str, Any],
        source_service: str,
        key: str | None = None,
        schema_version: str = "1.0",
    ) -> None:
        """
        Publish a message with the standard Aegis envelope.
        key is used for partition routing — use asset_id or incident_id for ordering.
        """
        envelope = {
            "message_id": str(uuid.uuid4()),
            "topic": topic,
            "timestamp": datetime.utcnow().isoformat(),
            "source_service": source_service,
            "schema_version": schema_version,
            "payload": payload,
        }
        try:
            await self._producer.send_and_wait(topic, value=envelope, key=key)
            logger.debug("kafka_message_published", topic=topic, key=key)
        except KafkaError as e:
            logger.error("kafka_publish_failed", topic=topic, error=str(e))
            raise

    async def publish_batch(
        self,
        topic: str,
        payloads: list[dict[str, Any]],
        source_service: str,
        keys: list[str | None] | None = None,
    ) -> None:
        """Publish multiple messages efficiently."""
        for i, payload in enumerate(payloads):
            key = keys[i] if keys and i < len(keys) else None
            await self.publish(topic, payload, source_service, key)


# ---------------------------------------------------------------------------
# Consumer
# ---------------------------------------------------------------------------

class AegisConsumer:
    """
    Async Kafka consumer. Yields deserialized message envelopes.
    Handles deserialization errors gracefully without crashing the consumer loop.
    """

    def __init__(
        self,
        topics: list[str],
        group_id: str,
        bootstrap_servers: str | list[str],
        auto_offset_reset: str = "earliest",
        max_poll_records: int = 100,
    ) -> None:
        servers = (
            bootstrap_servers
            if isinstance(bootstrap_servers, list)
            else [bootstrap_servers]
        )
        self._consumer = AIOKafkaConsumer(
            *topics,
            bootstrap_servers=servers,
            group_id=group_id,
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            auto_offset_reset=auto_offset_reset,
            enable_auto_commit=True,
            auto_commit_interval_ms=5_000,
            max_poll_records=max_poll_records,
            session_timeout_ms=30_000,
            heartbeat_interval_ms=10_000,
        )
        self.topics = topics
        self.group_id = group_id

    async def start(self) -> None:
        await self._consumer.start()
        logger.info(
            "kafka_consumer_started",
            topics=self.topics,
            group_id=self.group_id,
        )

    async def stop(self) -> None:
        await self._consumer.stop()
        logger.info("kafka_consumer_stopped")

    async def stream(self) -> AsyncIterator[dict[str, Any]]:
        """
        Async generator. Yields message envelopes (the full KafkaMessage dict).
        On deserialization errors, logs and skips — never crashes.
        """
        async for message in self._consumer:
            try:
                yield message.value  # Already deserialized by value_deserializer
            except Exception as e:
                logger.error(
                    "kafka_message_deserialization_failed",
                    topic=message.topic,
                    partition=message.partition,
                    offset=message.offset,
                    error=str(e),
                )
                continue


# ---------------------------------------------------------------------------
# Topic constants — single source of truth
# ---------------------------------------------------------------------------

class Topics:
    ASSETS_DISCOVERED = "aegis.assets.discovered"
    TELEMETRY_RAW = "aegis.telemetry.raw"
    TELEMETRY_NORMALIZED = "aegis.telemetry.normalized"
    THREAT_INTEL_FEEDS = "aegis.threat-intel.feeds"
    THREAT_INTEL_ENRICHED = "aegis.threat-intel.enriched"
    DETECTIONS_ALERTS = "aegis.detections.alerts"
    DETECTIONS_CORRELATED = "aegis.detections.correlated"
    INCIDENTS_CREATED = "aegis.incidents.created"
    INCIDENTS_UPDATED = "aegis.incidents.updated"
    AGENTS_TASKS = "aegis.agents.tasks"
    AGENTS_RESULTS = "aegis.agents.results"
    RESPONSE_PROPOSED = "aegis.response.proposed"
    RESPONSE_APPROVED = "aegis.response.approved"
    RESPONSE_EXECUTED = "aegis.response.executed"
    GRAPH_UPDATES = "aegis.graph.updates"
    AUDIT_EVENTS = "aegis.audit.events"
