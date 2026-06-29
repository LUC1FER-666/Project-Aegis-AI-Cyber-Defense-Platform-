import asyncio
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.redis_client import redis_client
from app.core.config import settings
from app.models.timeline_event import TimelineEvent
from app.models.schemas import TimelineEventOut, TimelineStats
from app.services.timeline_collector import CHANNEL

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("", response_model=list[TimelineEventOut])
async def get_timeline(
    limit: int = Query(100, ge=1, le=500),
    event_type: str | None = Query(None),
    severity: str | None = Query(None),
    asset_id: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Return last N timeline events from Redis cache, filtered optionally."""
    # Try Redis first for speed
    raw_events = await redis_client.zrevrange(settings.REDIS_TIMELINE_CACHE, 0, limit - 1)
    if raw_events:
        events = []
        for raw in raw_events:
            try:
                ev = json.loads(raw)
                # Apply filters
                if event_type and ev.get("event_type") != event_type:
                    continue
                if severity and ev.get("severity") != severity:
                    continue
                if asset_id and asset_id not in ev.get("asset_ids", []):
                    continue
                events.append(TimelineEventOut(
                    event_id=ev["event_id"],
                    event_type=ev["event_type"],
                    severity=ev.get("severity", "info"),
                    title=ev.get("title", ""),
                    description=ev.get("description", ""),
                    source_service=ev.get("source_service", ""),
                    source_id=ev.get("source_id", ""),
                    asset_ids=ev.get("asset_ids", []),
                    mitre_techniques=ev.get("mitre_techniques", []),
                    extra_data=ev.get("extra_data"),
                    timestamp=datetime.fromisoformat(ev["timestamp"]),
                    created_at=datetime.fromisoformat(ev.get("created_at", ev["timestamp"])),
                ))
            except Exception:
                continue
        return events[:limit]

    # Fallback to PostgreSQL
    query = select(TimelineEvent).order_by(TimelineEvent.timestamp.desc())
    if event_type:
        query = query.where(TimelineEvent.event_type == event_type)
    if severity:
        query = query.where(TimelineEvent.severity == severity)
    query = query.limit(limit)

    result = await db.execute(query)
    events = result.scalars().all()

    if asset_id:
        events = [e for e in events if asset_id in (e.asset_ids or [])]

    return [TimelineEventOut.model_validate(e) for e in events]


@router.get("/stats", response_model=TimelineStats)
async def get_timeline_stats(db: AsyncSession = Depends(get_db)):
    """Return counts by event_type, by severity, events per hour and per 24h."""
    now = datetime.now(timezone.utc)
    hour_ago = now - timedelta(hours=1)
    day_ago = now - timedelta(hours=24)

    total_result = await db.execute(select(func.count()).select_from(TimelineEvent))
    total = total_result.scalar() or 0

    type_result = await db.execute(
        select(TimelineEvent.event_type, func.count().label("cnt"))
        .group_by(TimelineEvent.event_type)
    )
    by_type = {row.event_type: row.cnt for row in type_result}

    sev_result = await db.execute(
        select(TimelineEvent.severity, func.count().label("cnt"))
        .group_by(TimelineEvent.severity)
    )
    by_severity = {row.severity: row.cnt for row in sev_result}

    hour_result = await db.execute(
        select(func.count()).select_from(TimelineEvent).where(TimelineEvent.timestamp >= hour_ago)
    )
    events_last_hour = hour_result.scalar() or 0

    day_result = await db.execute(
        select(func.count()).select_from(TimelineEvent).where(TimelineEvent.timestamp >= day_ago)
    )
    events_last_24h = day_result.scalar() or 0

    return TimelineStats(
        total_events=total,
        by_type=by_type,
        by_severity=by_severity,
        events_last_hour=events_last_hour,
        events_last_24h=events_last_24h,
    )


@router.get("/stream")
async def stream_timeline():
    """SSE stream of new timeline events — broadcasts via Redis pub/sub."""

    async def event_generator() -> AsyncGenerator[str, None]:
        # Send keep-alive comment immediately
        yield ": connected\n\n"

        pubsub = await redis_client.subscribe(CHANNEL)
        if pubsub is None:
            # Redis unavailable — send heartbeats only
            while True:
                yield ": heartbeat\n\n"
                await asyncio.sleep(15)
            return

        try:
            while True:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=15)
                if message and message.get("type") == "message":
                    data = message.get("data", "")
                    yield f"data: {data}\n\n"
                else:
                    yield ": heartbeat\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            try:
                await pubsub.unsubscribe(CHANNEL)
                await pubsub.aclose()
            except Exception:
                pass

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
