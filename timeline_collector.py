"""
TimelineCollector — polls Detection Engine, Agent Orchestrator, and Threat Defense Agent
every TIMELINE_POLL_INTERVAL seconds and builds a unified chronological timeline.
"""
import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy import select

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.redis_client import redis_client
from app.models.timeline_event import TimelineEvent

logger = logging.getLogger(__name__)

CHANNEL = "aegis:timeline:new_event"


class TimelineCollector:
    def __init__(self):
        self._http = httpx.AsyncClient(timeout=5.0)

    async def run_forever(self):
        logger.info("TimelineCollector started")
        while True:
            try:
                await self._collect_all()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Collector error: {e}")
            await asyncio.sleep(settings.TIMELINE_POLL_INTERVAL)
        await self._http.aclose()

    # ─── Main collection loop ─────────────────────────────────────────────────

    async def _collect_all(self):
        tasks = [
            self._collect_alerts(),
            self._collect_incidents(),
            self._collect_agent_tasks(),
            self._collect_predictions(),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                logger.debug(f"Collection sub-task error: {r}")

    # ─── Per-service collectors ───────────────────────────────────────────────

    async def _collect_alerts(self):
        try:
            resp = await self._http.get(
                f"{settings.DETECTION_ENGINE_URL}/api/v1/alerts?limit=100"
            )
            if resp.status_code != 200:
                return
            data = resp.json()
            alerts = data if isinstance(data, list) else data.get("alerts", data.get("items", []))
            for alert in alerts:
                await self._upsert_event(
                    event_type="alert",
                    source_service="detection-engine",
                    source_id=alert.get("alert_id") or alert.get("id", ""),
                    severity=alert.get("severity", "info"),
                    title=f"Alert: {alert.get('rule_id', 'Unknown Rule')}",
                    description=(
                        f"MITRE {alert.get('mitre_technique', 'N/A')} detected "
                        f"on asset {alert.get('asset_id', 'unknown')} "
                        f"with confidence {alert.get('confidence_score', 0):.2f}"
                    ),
                    asset_ids=[alert["asset_id"]] if alert.get("asset_id") else [],
                    mitre_techniques=[alert["mitre_technique"]] if alert.get("mitre_technique") else [],
                    timestamp_str=alert.get("created_at"),
                    extra_data={
                        "rule_id": alert.get("rule_id"),
                        "confidence_score": alert.get("confidence_score"),
                        "llm_validated": alert.get("llm_validated"),
                        "status": alert.get("status"),
                        "source_log_type": alert.get("source_log_type"),
                    },
                )
        except Exception as e:
            logger.debug(f"collect_alerts error: {e}")

    async def _collect_incidents(self):
        try:
            resp = await self._http.get(
                f"{settings.DETECTION_ENGINE_URL}/api/v1/incidents?limit=50"
            )
            if resp.status_code != 200:
                return
            data = resp.json()
            incidents = data if isinstance(data, list) else data.get("incidents", data.get("items", []))
            for inc in incidents:
                await self._upsert_event(
                    event_type="incident",
                    source_service="detection-engine",
                    source_id=inc.get("incident_id") or inc.get("id", ""),
                    severity=inc.get("severity", "info"),
                    title=f"Incident: {inc.get('title', 'Unknown')}",
                    description=(
                        f"{inc.get('alert_count', 0)} alerts correlated across "
                        f"{len(inc.get('affected_assets', []))} assets"
                    ),
                    asset_ids=inc.get("affected_assets", []),
                    mitre_techniques=inc.get("mitre_techniques", []),
                    timestamp_str=inc.get("created_at"),
                    extra_data={
                        "status": inc.get("status"),
                        "alert_count": inc.get("alert_count"),
                        "correlation_key": inc.get("correlation_key"),
                        "first_seen": inc.get("first_seen"),
                        "last_seen": inc.get("last_seen"),
                    },
                )
        except Exception as e:
            logger.debug(f"collect_incidents error: {e}")

    async def _collect_agent_tasks(self):
        try:
            resp = await self._http.get(
                f"{settings.AGENT_ORCHESTRATOR_URL}/api/v1/tasks?page_size=50"
            )
            if resp.status_code != 200:
                return
            data = resp.json()
            tasks = data if isinstance(data, list) else data.get("tasks", data.get("items", []))
            for task in tasks:
                await self._upsert_event(
                    event_type="agent_task",
                    source_service="agent-orchestrator",
                    source_id=task.get("id", ""),
                    severity=task.get("severity", "info"),
                    title=f"Agent Task: {task.get('selected_playbook', 'Investigation')}",
                    description=(
                        f"Responding to incident '{task.get('incident_title', 'Unknown')}' "
                        f"— status: {task.get('status', 'unknown')}"
                    ),
                    asset_ids=[],
                    mitre_techniques=[],
                    timestamp_str=task.get("created_at"),
                    extra_data={
                        "status": task.get("status"),
                        "incident_id": task.get("incident_id"),
                        "playbook": task.get("selected_playbook"),
                        "approved_by": task.get("approved_by"),
                    },
                )
        except Exception as e:
            logger.debug(f"collect_agent_tasks error: {e}")

    async def _collect_predictions(self):
        try:
            resp = await self._http.get(
                f"{settings.THREAT_DEFENSE_URL}/api/v1/predictions"
            )
            if resp.status_code != 200:
                return
            data = resp.json()
            predictions = data if isinstance(data, list) else data.get("predictions", data.get("items", []))
            for pred in predictions:
                confidence = pred.get("confidence", pred.get("confidence_score", 0))
                severity = (
                    "critical" if confidence >= 0.9
                    else "high" if confidence >= 0.75
                    else "medium" if confidence >= 0.5
                    else "low"
                )
                await self._upsert_event(
                    event_type="prediction",
                    source_service="threat-defense-agent",
                    source_id=str(pred.get("prediction_id", pred.get("id", ""))),
                    severity=severity,
                    title=f"Threat Prediction: {pred.get('threat_type', pred.get('detector_name', 'Unknown'))}",
                    description=(
                        f"Predicted attack with confidence {confidence:.2f} "
                        f"— {pred.get('description', pred.get('reasoning', ''))[:120]}"
                    ),
                    asset_ids=pred.get("affected_assets", []),
                    mitre_techniques=pred.get("mitre_techniques", []),
                    timestamp_str=pred.get("created_at"),
                    extra_data={
                        "confidence": confidence,
                        "threat_type": pred.get("threat_type", pred.get("detector_name")),
                        "status": pred.get("status"),
                    },
                )
        except Exception as e:
            logger.debug(f"collect_predictions error: {e}")

    # ─── Upsert helper ────────────────────────────────────────────────────────

    async def _upsert_event(
        self,
        event_type: str,
        source_service: str,
        source_id: str,
        severity: str,
        title: str,
        description: str,
        asset_ids: list[str],
        mitre_techniques: list[str],
        timestamp_str: str | None,
        extra_data: dict | None,
    ):
        if not source_id:
            return

        seen_key = f"{settings.REDIS_SEEN_PREFIX}:{event_type}"
        if await redis_client.sismember(seen_key, source_id):
            return  # Already processed

        # Parse timestamp
        timestamp = _parse_dt(timestamp_str)

        event_id = f"{event_type}:{source_id}"

        # Persist to PostgreSQL
        async with AsyncSessionLocal() as db:
            existing = await db.execute(
                select(TimelineEvent).where(TimelineEvent.event_id == event_id)
            )
            if existing.scalar_one_or_none() is not None:
                await redis_client.sadd(seen_key, source_id)
                return

            ev = TimelineEvent(
                id=str(uuid.uuid4()),
                event_id=event_id,
                event_type=event_type,
                severity=severity,
                title=title,
                description=description,
                source_service=source_service,
                source_id=source_id,
                asset_ids=asset_ids,
                mitre_techniques=mitre_techniques,
                extra_data=extra_data,
                timestamp=timestamp,
            )
            db.add(ev)
            await db.commit()
            await db.refresh(ev)

        # Mark as seen
        await redis_client.sadd(seen_key, source_id)

        # Add to Redis sorted set (score = unix timestamp)
        ts_score = timestamp.timestamp()
        payload = json.dumps({
            "event_id": event_id,
            "event_type": event_type,
            "severity": severity,
            "title": title,
            "description": description,
            "source_service": source_service,
            "source_id": source_id,
            "asset_ids": asset_ids,
            "mitre_techniques": mitre_techniques,
            "extra_data": extra_data,
            "timestamp": timestamp.isoformat(),
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        await redis_client.zadd(settings.REDIS_TIMELINE_CACHE, {payload: ts_score})

        # Trim to max size
        total = await redis_client.zcard(settings.REDIS_TIMELINE_CACHE)
        if total > settings.REDIS_TIMELINE_MAX:
            await redis_client.zremrangebyrank(
                settings.REDIS_TIMELINE_CACHE, 0, total - settings.REDIS_TIMELINE_MAX - 1
            )

        # Publish for SSE
        await redis_client.publish(CHANNEL, payload)
        logger.info(f"New timeline event: {event_type} / {source_id}")


def _parse_dt(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.now(timezone.utc)
