"""
Telemetry ingestion endpoints.

POST /telemetry/events        — single event (from agents)
POST /telemetry/events/batch  — bulk ingest (from log shippers)
POST /telemetry/syslog        — syslog UDP relay
GET  /telemetry/stats         — ingestion statistics
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

import sys
sys.path.insert(0, "/shared/python")
from aegis_common.kafka import AegisProducer, Topics
from aegis_common.logging import get_logger

from app.main import normalizer

logger = get_logger(__name__)
router = APIRouter(tags=["Telemetry Ingestion"])

# In-memory ingestion counters (Prometheus metrics cover persistence)
_stats: dict[str, int] = {
    "total_received": 0,
    "total_indexed": 0,
    "total_errors": 0,
}


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class EventIngest(BaseModel):
    """Single event from an agent or log forwarder."""
    source_type: str = Field(
        ...,
        description="Log format: windows_event | syslog | auditd | netflow | dns | auth | process | generic",
    )
    asset_id: str | None = Field(None, description="Asset UUID if known")
    payload: dict[str, Any] = Field(..., description="Raw log payload")


class BatchIngest(BaseModel):
    """Bulk ingest — up to 1000 events per request."""
    events: list[EventIngest] = Field(..., max_length=1000)


class IngestResponse(BaseModel):
    accepted: int
    failed: int
    event_ids: list[str]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get_es_client():
    """Lazy Elasticsearch client."""
    from app.config import get_settings
    settings = get_settings()
    return settings.elasticsearch_url


async def _index_event(es_url: str, event: dict[str, Any]) -> bool:
    """Index a single normalized event to Elasticsearch."""
    today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    index = f"aegis-events-{today}"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{es_url}/{index}/_doc/{event['event_id']}",
                json=event,
            )
            return resp.status_code in (200, 201)
    except Exception as e:
        logger.error("elasticsearch_index_failed", error=str(e))
        return False


async def _publish_to_kafka(event: dict[str, Any]) -> None:
    """Publish normalized event to Kafka for real-time detection."""
    try:
        from app.kafka_client import get_producer
        producer = await get_producer()
        await producer.publish(
            topic=Topics.TELEMETRY_NORMALIZED,
            payload=event,
            source_service="telemetry-collector",
            key=event.get("asset_id") or event.get("asset_ip"),
        )
    except Exception as e:
        logger.error("kafka_publish_failed", error=str(e))


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/telemetry/events",
    response_model=IngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest a single telemetry event",
)
async def ingest_event(body: EventIngest) -> IngestResponse:
    """
    Accept a single log event, normalize it, index to Elasticsearch,
    and publish to Kafka for real-time detection.
    """
    _stats["total_received"] += 1
    es_url = await _get_es_client()

    normalized = normalizer.normalize(body.payload, body.source_type)
    if body.asset_id:
        normalized["asset_id"] = body.asset_id

    # Publish raw to Kafka first (for replay capability)
    try:
        from app.kafka_client import get_producer
        producer = await get_producer()
        await producer.publish(
            topic=Topics.TELEMETRY_RAW,
            payload={"source_type": body.source_type, "raw": body.payload},
            source_service="telemetry-collector",
        )
    except Exception as e:
        logger.warning("raw_kafka_publish_failed", error=str(e))

    # Index normalized event to Elasticsearch
    success = await _index_event(es_url, normalized)

    if success:
        # Publish normalized for detection engine
        await _publish_to_kafka(normalized)
        _stats["total_indexed"] += 1
        return IngestResponse(accepted=1, failed=0, event_ids=[normalized["event_id"]])
    else:
        _stats["total_errors"] += 1
        return IngestResponse(accepted=0, failed=1, event_ids=[])


@router.post(
    "/telemetry/events/batch",
    response_model=IngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Bulk ingest telemetry events (max 1000)",
)
async def ingest_batch(body: BatchIngest) -> IngestResponse:
    """
    Bulk endpoint for log shippers (Filebeat, Fluentd, Vector).
    Processes events concurrently for throughput.
    """
    import asyncio

    _stats["total_received"] += len(body.events)
    es_url = await _get_es_client()

    accepted_ids: list[str] = []
    failed = 0

    # Normalize all events
    normalized_events = []
    for event in body.events:
        try:
            normalized = normalizer.normalize(event.payload, event.source_type)
            if event.asset_id:
                normalized["asset_id"] = event.asset_id
            normalized_events.append(normalized)
        except Exception as e:
            logger.warning("normalization_failed", error=str(e))
            failed += 1

    # Bulk index to Elasticsearch using _bulk API
    if normalized_events:
        today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
        index = f"aegis-events-{today}"

        # Build NDJSON bulk body
        bulk_lines = []
        for event in normalized_events:
            bulk_lines.append(
                f'{{"index":{{"_index":"{index}","_id":"{event["event_id"]}"}}}}'
            )
            import json
            bulk_lines.append(json.dumps(event, default=str))
        bulk_body = "\n".join(bulk_lines) + "\n"

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    f"{es_url}/_bulk",
                    content=bulk_body,
                    headers={"Content-Type": "application/x-ndjson"},
                )
                if resp.status_code == 200:
                    result = resp.json()
                    # Count successes and failures from bulk response
                    for item in result.get("items", []):
                        idx = item.get("index", {})
                        if idx.get("status") in (200, 201):
                            accepted_ids.append(idx.get("_id", ""))
                        else:
                            failed += 1
                else:
                    failed += len(normalized_events)
        except Exception as e:
            logger.error("bulk_index_failed", error=str(e))
            failed += len(normalized_events)

        # Publish to Kafka (fire and forget for each)
        for event in normalized_events:
            if event["event_id"] in accepted_ids:
                await _publish_to_kafka(event)

    _stats["total_indexed"] += len(accepted_ids)
    _stats["total_errors"] += failed

    logger.info(
        "batch_ingested",
        accepted=len(accepted_ids),
        failed=failed,
        total=len(body.events),
    )

    return IngestResponse(
        accepted=len(accepted_ids),
        failed=failed,
        event_ids=accepted_ids,
    )


@router.get(
    "/telemetry/stats",
    summary="Ingestion statistics",
)
async def get_stats() -> dict:
    """Return running ingestion counters."""
    return {
        **_stats,
        "uptime_since": datetime.now(timezone.utc).isoformat(),
    }


@router.get(
    "/telemetry/search",
    summary="Search events in Elasticsearch",
)
async def search_events(
    asset_ip: str | None = None,
    event_type: str | None = None,
    hours: int = 24,
    size: int = 100,
) -> dict:
    """
    Simple event search — used by the investigation service and frontend.
    For complex queries, use Kibana or direct Elasticsearch access.
    """
    from app.config import get_settings
    settings = get_settings()

    must_clauses = []
    if asset_ip:
        must_clauses.append({"term": {"asset_ip": asset_ip}})
    if event_type:
        must_clauses.append({"term": {"event_type": event_type}})

    must_clauses.append({
        "range": {
            "@timestamp": {
                "gte": f"now-{hours}h",
                "lte": "now",
            }
        }
    })

    query = {
        "query": {"bool": {"must": must_clauses}},
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": min(size, 1000),
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{settings.elasticsearch_url}/aegis-events-*/_search",
                json=query,
            )
            if resp.status_code == 200:
                data = resp.json()
                hits = data.get("hits", {})
                return {
                    "total": hits.get("total", {}).get("value", 0),
                    "events": [h["_source"] for h in hits.get("hits", [])],
                }
    except Exception as e:
        logger.error("search_failed", error=str(e))

    return {"total": 0, "events": []}
