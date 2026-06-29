"""
Detection Engine — Kafka Consumer & Publisher

Consumer: aegis.telemetry.normalized
Publisher: aegis.detections.alerts, aegis.incidents.created, aegis.graph.updates
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from app.config import settings
from app.database import get_db_context

logger = logging.getLogger(__name__)


class KafkaPublisher:
    """Publishes detection results to Kafka topics."""

    def __init__(self, bootstrap_servers: str):
        self.bootstrap_servers = bootstrap_servers
        self._producer = None

    async def start(self) -> None:
        try:
            from aiokafka import AIOKafkaProducer
            self._producer = AIOKafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
                acks="all",
                enable_idempotence=True,
            )
            await self._producer.start()
            logger.info("Kafka producer started")
        except Exception as exc:
            logger.warning("Kafka producer failed to start (running without Kafka): %s", exc)
            self._producer = None

    async def stop(self) -> None:
        if self._producer:
            await self._producer.stop()

    async def publish_alert(self, alert_data: dict[str, Any]) -> None:
        """Publish to aegis.detections.alerts."""
        await self._send("aegis.detections.alerts", alert_data, key=alert_data.get("rule_id"))

    async def publish_incident(self, incident) -> None:
        """Publish to aegis.incidents.created."""
        payload = {
            "incident_id": str(incident.id),
            "title": incident.title,
            "severity": incident.severity.value,
            "mitre_techniques": incident.mitre_techniques,
            "affected_assets": incident.affected_assets,
            "alert_count": incident.alert_count,
            "first_seen": incident.first_seen.isoformat() if incident.first_seen else None,
            "last_seen": incident.last_seen.isoformat() if incident.last_seen else None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await self._send("aegis.incidents.created", payload, key=str(incident.id))

    async def _send(self, topic: str, payload: dict, key: Optional[str] = None) -> None:
        if not self._producer:
            logger.debug("Kafka not available — dropping %s message", topic)
            return
        try:
            await self._producer.send_and_wait(topic, value=payload, key=key)
        except Exception as exc:
            logger.warning("Failed to publish to %s: %s", topic, exc)


class TelemetryConsumer:
    """
    Consumes normalised telemetry events from aegis.telemetry.normalized
    and feeds them through the detection pipeline.
    """

    def __init__(self, pipeline, publisher: KafkaPublisher):
        self.pipeline = pipeline
        self.publisher = publisher
        self._consumer = None
        self._running = False

    async def start(self) -> None:
        try:
            from aiokafka import AIOKafkaConsumer
            self._consumer = AIOKafkaConsumer(
                "aegis.telemetry.normalized",
                bootstrap_servers=settings.kafka_bootstrap_servers,
                group_id=settings.kafka_consumer_group,
                value_deserializer=lambda v: json.loads(v.decode("utf-8")),
                auto_offset_reset="latest",
                enable_auto_commit=True,
                max_poll_records=50,
            )
            await self._consumer.start()
            self._running = True
            logger.info("Telemetry consumer started")
            asyncio.create_task(self._consume_loop())
            asyncio.create_task(self._sweep_loop())
        except Exception as exc:
            logger.warning("Kafka consumer failed to start: %s", exc)

    async def stop(self) -> None:
        self._running = False
        if self._consumer:
            await self._consumer.stop()

    async def _consume_loop(self) -> None:
        """Main consumption loop."""
        while self._running:
            try:
                async for msg in self._consumer:
                    if not self._running:
                        break
                    try:
                        await self._process_message(msg.value)
                    except Exception as exc:
                        logger.error("Error processing telemetry event: %s", exc, exc_info=True)
            except Exception as exc:
                logger.error("Consumer loop error: %s", exc)
                if self._running:
                    await asyncio.sleep(5)

    async def _process_message(self, event: dict[str, Any]) -> None:
        """Process a single telemetry event through the pipeline."""
        async with get_db_context() as db:
            alerts = await self.pipeline.process_event(event, db)
            for alert_data in alerts:
                await self.publisher.publish_alert(alert_data)

    async def _sweep_loop(self) -> None:
        """Periodically emit incidents from expired correlation buckets."""
        while self._running:
            await asyncio.sleep(60)  # sweep every minute
            try:
                incidents = await self.pipeline.correlator.sweep_expired()
                async with get_db_context() as db:
                    for corr_incident in incidents:
                        from app.models import Alert, Incident, IncidentStatus
                        from app.pipeline import SEVERITY_MAP
                        severity = SEVERITY_MAP.get(corr_incident.severity)
                        incident = Incident(
                            title=corr_incident.title,
                            description=corr_incident.description,
                            severity=severity,
                            status=IncidentStatus.OPEN,
                            mitre_techniques=corr_incident.mitre_techniques,
                            affected_assets=corr_incident.affected_assets,
                            alert_count=corr_incident.alert_count,
                            correlation_key=corr_incident.correlation_key,
                            first_seen=corr_incident.first_seen,
                            last_seen=corr_incident.last_seen,
                        )
                        db.add(incident)
                        await db.flush()
                        await self.publisher.publish_incident(incident)
            except Exception as exc:
                logger.error("Sweep loop error: %s", exc)
