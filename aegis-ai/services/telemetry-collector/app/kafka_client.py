"""Kafka producer singleton for telemetry-collector."""
from __future__ import annotations
import sys
sys.path.insert(0, "/shared/python")
from aegis_common.kafka import AegisProducer
from app.config import get_settings

settings = get_settings()
_producer: AegisProducer | None = None


async def get_producer() -> AegisProducer:
    global _producer
    if _producer is None:
        _producer = AegisProducer(bootstrap_servers=settings.kafka_servers_list)
        await _producer._producer.start()
    return _producer


async def close_producer() -> None:
    global _producer
    if _producer is not None:
        await _producer._producer.stop()
        _producer = None
