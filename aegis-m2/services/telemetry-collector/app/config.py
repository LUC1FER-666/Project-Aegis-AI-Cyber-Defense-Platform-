"""Telemetry Collector configuration."""
from functools import lru_cache
import sys
sys.path.insert(0, "/shared/python")
from aegis_common.config import BaseServiceSettings


class TelemetrySettings(BaseServiceSettings):
    service_name: str = "telemetry-collector"
    service_port: int = 8002

    # Elasticsearch
    elasticsearch_index_prefix: str = "aegis-events"
    elasticsearch_max_batch_size: int = 1000

    # Kafka
    kafka_raw_topic: str = "aegis.telemetry.raw"
    kafka_normalized_topic: str = "aegis.telemetry.normalized"


@lru_cache
def get_settings() -> TelemetrySettings:
    return TelemetrySettings()
