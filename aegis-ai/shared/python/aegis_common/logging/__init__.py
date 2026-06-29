"""
Structured logging for all Aegis services.
Uses structlog for JSON output in production, colored console in dev.

Usage:
    from aegis_common.logging import get_logger
    logger = get_logger(__name__)
    logger.info("event_name", key="value", incident_id=str(incident_id))
"""
import logging
import sys
from typing import Any

import structlog
from structlog.types import EventDict, Processor


def add_service_context(service_name: str, service_version: str = "0.1.0") -> Processor:
    """Inject service identity into every log record."""

    def processor(logger: Any, method: str, event_dict: EventDict) -> EventDict:
        event_dict["service"] = service_name
        event_dict["version"] = service_version
        return event_dict

    return processor


def configure_logging(
    service_name: str,
    log_level: str = "INFO",
    environment: str = "development",
) -> None:
    """
    Call once at service startup in main.py.
    JSON output in production, human-readable in development.
    """
    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        add_service_context(service_name),
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
    ]

    if environment == "production":
        # JSON lines — ingested by Elasticsearch / log aggregators
        renderer: Processor = structlog.processors.JSONRenderer()
    else:
        # Color-coded for local dev
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            *shared_processors,
            renderer,
        ]
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(log_level.upper())

    # Silence noisy libraries
    for noisy_lib in ["uvicorn.access", "kafka", "asyncio"]:
        logging.getLogger(noisy_lib).setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a structured logger. Use module __name__ as the name."""
    return structlog.get_logger(name)
