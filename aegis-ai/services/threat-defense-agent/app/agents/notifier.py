"""
SOC Notification System
Stores notifications in PostgreSQL and streams them via SSE.
SSE handles client disconnects gracefully — never crashes the server.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, AsyncIterator

logger = logging.getLogger(__name__)

# In-process subscriber queues for SSE — keyed by subscriber ID
_subscribers: dict[str, asyncio.Queue] = {}


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def register_subscriber(sub_id: str) -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=100)
    _subscribers[sub_id] = q
    logger.debug("SSE subscriber registered: %s (total=%d)", sub_id, len(_subscribers))
    return q


def unregister_subscriber(sub_id: str) -> None:
    _subscribers.pop(sub_id, None)
    logger.debug("SSE subscriber removed: %s (total=%d)", sub_id, len(_subscribers))


async def broadcast(notification: dict[str, Any]) -> None:
    """Push notification to all connected SSE subscribers."""
    if not _subscribers:
        return
    dead = []
    for sub_id, q in _subscribers.items():
        try:
            q.put_nowait(notification)
        except asyncio.QueueFull:
            logger.warning("SSE queue full for subscriber %s — dropping message", sub_id)
        except Exception as exc:
            logger.warning("SSE broadcast error for %s: %s", sub_id, exc)
            dead.append(sub_id)
    for sub_id in dead:
        unregister_subscriber(sub_id)


async def sse_event_stream(sub_id: str, q: asyncio.Queue) -> AsyncIterator[str]:
    """
    Async generator for SSE events.
    Sends a heartbeat every 15 seconds so proxies don't close the connection.
    Handles client disconnect gracefully.
    """
    try:
        yield "event: connected\ndata: {\"status\": \"connected\"}\n\n"
        while True:
            try:
                notification = await asyncio.wait_for(q.get(), timeout=15.0)
                payload = json.dumps(notification)
                yield f"event: notification\ndata: {payload}\n\n"
            except asyncio.TimeoutError:
                # Heartbeat keep-alive
                yield "event: heartbeat\ndata: {}\n\n"
    except asyncio.CancelledError:
        logger.debug("SSE stream cancelled for subscriber %s", sub_id)
    except GeneratorExit:
        logger.debug("SSE stream generator exit for subscriber %s", sub_id)
    except Exception as exc:
        logger.warning("SSE stream error for subscriber %s: %s", sub_id, exc)
    finally:
        unregister_subscriber(sub_id)


class SOCNotificationSystem:
    """Creates and broadcasts structured SOC notifications."""

    def build(
        self,
        notification_type: str,
        title: str,
        body: str,
        severity: str,
        asset_ids: list[str] | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "notification_type": notification_type,
            "title": title,
            "body": body,
            "severity": severity,
            "read": False,
            "asset_ids": asset_ids or [],
            "evidence": evidence or {},
            "created_at": _now().isoformat(),
        }

    def prediction_alert(self, prediction: dict[str, Any]) -> dict[str, Any]:
        threat = prediction.get("threat_type", "unknown").replace("_", " ")
        confidence = float(prediction.get("confidence") or 0)
        assets = prediction.get("affected_assets") or []
        actions = prediction.get("recommended_actions") or []

        return self.build(
            notification_type="prediction_alert",
            title=f"⚠ Imminent threat detected: {threat}",
            body=(
                f"Confidence: {confidence:.0%}. "
                f"Affected assets: {', '.join(str(a) for a in assets[:3])}. "
                f"Recommended actions: {', '.join(str(a) for a in actions[:3])}. "
                f"{prediction.get('evidence_summary', '')}"
            ),
            severity=_confidence_to_severity(confidence),
            asset_ids=[str(a) for a in assets],
            evidence={"prediction": prediction},
        )

    def attack_confirmed(self, incident: dict[str, Any]) -> dict[str, Any]:
        title = incident.get("title") or incident.get("incident_title") or "Security Incident"
        severity = str(incident.get("severity") or "medium")
        assets = incident.get("affected_assets") or incident.get("asset_ids") or []

        return self.build(
            notification_type="attack_confirmed",
            title=f"🔴 Attack confirmed: {title}",
            body=(
                f"Severity: {severity.upper()}. "
                f"Affected assets: {', '.join(str(a) for a in assets[:3])}. "
                f"Alert count: {incident.get('alert_count', 1)}."
            ),
            severity=severity,
            asset_ids=[str(a) for a in assets],
            evidence=incident,
        )

    def preemptive_action_taken(self, action: dict[str, Any], prediction: dict[str, Any]) -> dict[str, Any]:
        action_type = action.get("action_type", "unknown").replace("_", " ")
        confidence = float(action.get("confidence_trigger") or 0)

        return self.build(
            notification_type="preemptive_action_taken",
            title=f"🛡 Preemptive action executed: {action_type}",
            body=(
                f"Action taken on {action.get('target', 'unknown target')} "
                f"based on {prediction.get('threat_type', 'threat')} prediction "
                f"(confidence: {confidence:.0%}). "
                f"Status: {action.get('status', 'unknown')}."
            ),
            severity=_confidence_to_severity(confidence),
            asset_ids=[action.get("target", "")],
            evidence={"action": action, "prediction": prediction},
        )

    def briefing_ready(self, narrative: dict[str, Any], source_id: str) -> dict[str, Any]:
        return self.build(
            notification_type="briefing_ready",
            title=f"📋 Attack briefing ready: {narrative.get('headline', 'Threat briefing')}",
            body=(
                f"Assessment: {narrative.get('severity_assessment', '')}. "
                f"Objective: {narrative.get('likely_objective', '')}."
            ),
            severity="medium",
            evidence={"source_id": source_id, "narrative": narrative},
        )


def _confidence_to_severity(confidence: float) -> str:
    if confidence >= 0.9:
        return "critical"
    if confidence >= 0.8:
        return "high"
    if confidence >= 0.6:
        return "medium"
    return "low"
