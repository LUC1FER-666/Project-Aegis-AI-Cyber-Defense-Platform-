"""
Threat Defense Agent — API routes
Includes SSE endpoint for real-time push notifications.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.narrator import AttackNarrativeEngine
from app.agents.notifier import (
    SOCNotificationSystem,
    broadcast,
    register_subscriber,
    sse_event_stream,
    unregister_subscriber,
)
from app.database import get_db
from app.graph.defense_agent import run_defense_agent
from app.models import (
    AttackNarrative,
    PreemptiveAction,
    PredictionStatus,
    SOCNotification,
    ThreatPrediction,
)
from app.schemas import (
    AgentStatusResponse,
    AttackNarrativeOut,
    GenerateNarrativeRequest,
    PreemptiveActionOut,
    SOCNotificationOut,
    StatsResponse,
    ThreatPredictionOut,
)

router = APIRouter()
logger = logging.getLogger(__name__)

# In-memory agent state (last run)
_last_agent_state: dict[str, Any] = {}


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_prediction_or_404(prediction_id: str, db: AsyncSession) -> ThreatPrediction:
    result = await db.execute(
        select(ThreatPrediction).where(ThreatPrediction.prediction_id == prediction_id)
    )
    pred = result.scalar_one_or_none()
    if pred is None:
        raise HTTPException(status_code=404, detail=f"Prediction {prediction_id} not found")
    return pred


async def _save_notification(notif_dict: dict[str, Any], db: AsyncSession) -> SOCNotification:
    notif = SOCNotification(
        notification_type=notif_dict["notification_type"],
        title=notif_dict["title"],
        body=notif_dict["body"],
        severity=notif_dict["severity"],
        read=False,
        asset_ids=notif_dict.get("asset_ids"),
        evidence=notif_dict.get("evidence"),
    )
    db.add(notif)
    await db.flush()
    return notif


async def _save_prediction(pred_dict: dict[str, Any], db: AsyncSession) -> ThreatPrediction:
    existing = await db.execute(
        select(ThreatPrediction).where(ThreatPrediction.prediction_id == pred_dict["prediction_id"])
    )
    if existing.scalar_one_or_none():
        return existing.scalar_one_or_none()  # type: ignore

    expires_at = datetime.fromisoformat(pred_dict["expires_at"])
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    pred = ThreatPrediction(
        prediction_id=pred_dict["prediction_id"],
        threat_type=pred_dict["threat_type"],
        confidence=pred_dict["confidence"],
        affected_assets=pred_dict.get("affected_assets"),
        evidence_summary=pred_dict["evidence_summary"],
        predicted_attack_vector=pred_dict["predicted_attack_vector"],
        recommended_actions=pred_dict.get("recommended_actions"),
        status=PredictionStatus.ACTIVE,
        expires_at=expires_at,
    )
    db.add(pred)
    await db.flush()
    return pred


# ── Health / Stats ────────────────────────────────────────────────────────────

@router.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "service": "threat-defense-agent"}


@router.get("/stats", response_model=StatsResponse)
async def get_stats(db: AsyncSession = Depends(get_db)) -> StatsResponse:
    active_result = await db.execute(
        select(func.count(ThreatPrediction.id)).where(ThreatPrediction.status == PredictionStatus.ACTIVE)
    )
    unread_result = await db.execute(
        select(func.count(SOCNotification.id)).where(SOCNotification.read == False)  # noqa: E712
    )
    narratives_result = await db.execute(select(func.count(AttackNarrative.id)))
    actions_result = await db.execute(select(func.count(PreemptiveAction.id)))

    agent_status = "idle" if not _last_agent_state else "ready"

    return StatsResponse(
        active_predictions=active_result.scalar_one() or 0,
        notifications_unread=unread_result.scalar_one() or 0,
        narratives_generated=narratives_result.scalar_one() or 0,
        preemptive_actions_taken=actions_result.scalar_one() or 0,
        agent_status=agent_status,
    )


# ── Predictions ───────────────────────────────────────────────────────────────

@router.get("/api/v1/predictions", response_model=list[ThreatPredictionOut])
async def list_predictions(
    threat_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
) -> list[ThreatPredictionOut]:
    stmt = select(ThreatPrediction).order_by(ThreatPrediction.created_at.desc())
    if threat_type:
        stmt = stmt.where(ThreatPrediction.threat_type == threat_type)
    if status:
        try:
            stmt = stmt.where(ThreatPrediction.status == PredictionStatus(status))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
    rows = await db.execute(stmt)
    return [ThreatPredictionOut.model_validate(p) for p in rows.scalars().all()]


@router.get("/api/v1/predictions/{prediction_id}", response_model=ThreatPredictionOut)
async def get_prediction(prediction_id: str, db: AsyncSession = Depends(get_db)) -> ThreatPredictionOut:
    pred = await _get_prediction_or_404(prediction_id, db)
    return ThreatPredictionOut.model_validate(pred)


@router.post("/api/v1/predictions/analyze")
async def manual_analyze(db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """
    Manually trigger pattern analysis against recent alerts from the detection engine.
    Fetches alerts, runs predictor, stores results.
    """
    import httpx
    from app.config import get_settings
    from app.agents.predictor import PredictiveThreatMonitor

    settings = get_settings()
    events: list[dict[str, Any]] = []

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{settings.detection_engine_url}/api/v1/alerts?limit=200")
            if resp.status_code == 200:
                data = resp.json()
                events = data if isinstance(data, list) else data.get("alerts", [])
    except Exception as exc:
        logger.warning("Could not fetch alerts from detection engine: %s", exc)

    monitor = PredictiveThreatMonitor()
    predictions = monitor.analyze(events)

    saved = []
    for pred_dict in predictions:
        pred = await _save_prediction(pred_dict, db)
        saved.append(pred_dict)

        # Broadcast notification
        notifier = SOCNotificationSystem()
        notif_dict = notifier.prediction_alert(pred_dict)
        await broadcast(notif_dict)
        await _save_notification(notif_dict, db)

    await db.commit()
    return {"predictions_created": len(saved), "predictions": saved}


# ── Narratives ────────────────────────────────────────────────────────────────

@router.get("/api/v1/narratives", response_model=list[AttackNarrativeOut])
async def list_narratives(db: AsyncSession = Depends(get_db)) -> list[AttackNarrativeOut]:
    rows = await db.execute(select(AttackNarrative).order_by(AttackNarrative.created_at.desc()))
    return [AttackNarrativeOut.model_validate(n) for n in rows.scalars().all()]


@router.get("/api/v1/narratives/{narrative_id}", response_model=AttackNarrativeOut)
async def get_narrative(narrative_id: str, db: AsyncSession = Depends(get_db)) -> AttackNarrativeOut:
    result = await db.execute(select(AttackNarrative).where(AttackNarrative.id == narrative_id))
    narrative = result.scalar_one_or_none()
    if narrative is None:
        raise HTTPException(status_code=404, detail="Narrative not found")
    return AttackNarrativeOut.model_validate(narrative)


@router.post("/api/v1/narratives/generate", response_model=AttackNarrativeOut)
async def generate_narrative(
    body: GenerateNarrativeRequest, db: AsyncSession = Depends(get_db)
) -> AttackNarrativeOut:
    engine = AttackNarrativeEngine()
    result = await engine.generate(body.context)

    narrative = AttackNarrative(
        source_type=body.source_type,
        source_id=body.source_id,
        headline=result["headline"],
        severity_assessment=result["severity_assessment"],
        attack_timeline=result.get("attack_timeline"),
        likely_objective=result["likely_objective"],
        immediate_actions=result.get("immediate_actions"),
        technical_indicators=result.get("technical_indicators"),
        confidence=result["confidence"],
    )
    db.add(narrative)
    await db.commit()
    await db.refresh(narrative)

    # Broadcast briefing notification
    notifier = SOCNotificationSystem()
    notif_dict = notifier.briefing_ready(result, body.source_id)
    await broadcast(notif_dict)
    await _save_notification(notif_dict, db)
    await db.commit()

    return AttackNarrativeOut.model_validate(narrative)


# ── Notifications ─────────────────────────────────────────────────────────────

@router.get("/api/v1/notifications", response_model=list[SOCNotificationOut])
async def list_notifications(
    read: Optional[bool] = Query(None),
    severity: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
) -> list[SOCNotificationOut]:
    stmt = select(SOCNotification).order_by(SOCNotification.created_at.desc()).limit(100)
    if read is not None:
        stmt = stmt.where(SOCNotification.read == read)
    if severity:
        stmt = stmt.where(SOCNotification.severity == severity)
    rows = await db.execute(stmt)
    return [SOCNotificationOut.model_validate(n) for n in rows.scalars().all()]


@router.patch("/api/v1/notifications/{notification_id}/read", response_model=SOCNotificationOut)
async def mark_read(notification_id: str, db: AsyncSession = Depends(get_db)) -> SOCNotificationOut:
    result = await db.execute(select(SOCNotification).where(SOCNotification.id == notification_id))
    notif = result.scalar_one_or_none()
    if notif is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    notif.read = True
    await db.commit()
    await db.refresh(notif)
    return SOCNotificationOut.model_validate(notif)


@router.patch("/api/v1/notifications/read-all")
async def mark_all_read(db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    from sqlalchemy import update
    await db.execute(
        update(SOCNotification).where(SOCNotification.read == False).values(read=True)  # noqa: E712
    )
    await db.commit()
    return {"message": "All notifications marked as read"}


@router.get("/api/v1/notifications/stream")
async def notification_stream() -> StreamingResponse:
    """
    SSE endpoint for real-time push notifications.
    Each client gets its own queue. Handles disconnect gracefully.
    """
    sub_id = str(uuid.uuid4())
    q = register_subscriber(sub_id)

    async def event_gen():
        async for chunk in sse_event_stream(sub_id, q):
            yield chunk

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ── Agent ─────────────────────────────────────────────────────────────────────

@router.post("/api/v1/agent/run")
async def run_agent(db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """Manually trigger the defense agent loop."""
    global _last_agent_state

    import httpx
    from app.config import get_settings

    settings = get_settings()
    events: list[dict[str, Any]] = []
    incidents: list[dict[str, Any]] = []

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            alerts_resp = await client.get(f"{settings.detection_engine_url}/api/v1/alerts?limit=200")
            if alerts_resp.status_code == 200:
                data = alerts_resp.json()
                events = data if isinstance(data, list) else data.get("alerts", [])

            incidents_resp = await client.get(f"{settings.detection_engine_url}/api/v1/incidents?limit=50")
            if incidents_resp.status_code == 200:
                data = incidents_resp.json()
                incidents = data if isinstance(data, list) else data.get("incidents", [])
    except Exception as exc:
        logger.warning("Failed to fetch data for agent run: %s", exc)

    final_state = await run_defense_agent(events=events, incidents=incidents)
    _last_agent_state = dict(final_state)

    # Persist predictions and notifications to DB
    for pred_dict in (final_state.get("predictions") or []):
        try:
            await _save_prediction(pred_dict, db)
        except Exception as exc:
            logger.warning("Failed to save prediction: %s", exc)

    for notif_dict in (final_state.get("notifications_sent") or []):
        try:
            await _save_notification(notif_dict, db)
        except Exception as exc:
            logger.warning("Failed to save notification: %s", exc)

    for narrative_dict in (final_state.get("narratives") or []):
        try:
            n = AttackNarrative(
                source_type=narrative_dict.get("source_type", "manual"),
                source_id=narrative_dict.get("source_id", "agent_run"),
                headline=narrative_dict.get("headline", ""),
                severity_assessment=narrative_dict.get("severity_assessment", ""),
                attack_timeline=narrative_dict.get("attack_timeline"),
                likely_objective=narrative_dict.get("likely_objective", ""),
                immediate_actions=narrative_dict.get("immediate_actions"),
                technical_indicators=narrative_dict.get("technical_indicators"),
                confidence=float(narrative_dict.get("confidence") or 0.5),
            )
            db.add(n)
        except Exception as exc:
            logger.warning("Failed to save narrative: %s", exc)

    await db.commit()

    return {
        "status": "completed",
        "predictions_generated": len(final_state.get("predictions") or []),
        "actions_taken": len(final_state.get("actions_taken") or []),
        "narratives_generated": len(final_state.get("narratives") or []),
        "notifications_sent": len(final_state.get("notifications_sent") or []),
        "completed_at": final_state.get("completed_at"),
    }


@router.get("/api/v1/agent/status", response_model=AgentStatusResponse)
async def agent_status() -> AgentStatusResponse:
    return AgentStatusResponse(
        status="idle" if not _last_agent_state else "ready",
        current_threats=_last_agent_state.get("current_threats") or [],
        predictions=[p.get("prediction_id", "") for p in (_last_agent_state.get("predictions") or [])],
        narratives=[n.get("headline", "") for n in (_last_agent_state.get("narratives") or [])],
        actions_taken=[a.get("action_type", "") for a in (_last_agent_state.get("actions_taken") or [])],
        notifications_sent=[n.get("notification_type", "") for n in (_last_agent_state.get("notifications_sent") or [])],
    )
