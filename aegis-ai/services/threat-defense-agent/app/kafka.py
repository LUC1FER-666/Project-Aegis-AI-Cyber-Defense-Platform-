from __future__ import annotations

import json
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

_producer = None
_kafka_available = False


async def init_kafka(bootstrap_servers: str) -> None:
    global _producer, _kafka_available
    try:
        from aiokafka import AIOKafkaProducer
        p = AIOKafkaProducer(
            bootstrap_servers=bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        )
        await p.start()
        _producer = p
        _kafka_available = True
        logger.info("Kafka producer connected to %s", bootstrap_servers)
    except Exception as exc:
        logger.warning("Kafka unavailable (%s) — running without Kafka.", exc)
        _kafka_available = False


async def close_kafka() -> None:
    global _producer, _kafka_available
    if _producer is not None:
        try:
            await _producer.stop()
        except Exception:
            pass
        finally:
            _producer = None
            _kafka_available = False


async def publish(topic: str, message: dict[str, Any], key: Optional[str] = None) -> bool:
    if not _kafka_available or _producer is None:
        logger.debug("Kafka not available — dropping message to %s", topic)
        return False
    try:
        key_bytes = key.encode("utf-8") if key else None
        await _producer.send_and_wait(topic, value=message, key=key_bytes)
        return True
    except Exception as exc:
        logger.error("Failed to publish to %s: %s", topic, exc)
        return False


def is_available() -> bool:
    return _kafka_available
