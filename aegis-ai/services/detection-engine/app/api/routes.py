"""
Detection Engine — API Routes

GET  /health
GET  /stats
POST /events/analyze          — submit event for immediate analysis
GET  /rules                   — list all loaded rules
GET  /rules/{rule_id}
PATCH /rules/{rule_id}        — enable/disable, adjust severity
GET  /alerts                  — list alerts (paginated, filterable)
GET  /alerts/{alert_id}
PATCH /alerts/{alert_id}
GET  /incidents               — list incidents
GET  /incidents/{incident_id}
PATCH /incidents/{incident_id}
GET  /models                  — ML model status
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Alert, Incident, DetectionRule, AlertStatus, IncidentStatus, Severity
from app.schemas import (
    RuleRead, RuleUpdate,
    AlertRead, AlertUpdate,
    IncidentRead, IncidentUpdate,
    DetectionStats,
)

router = APIRouter()

# Pipeline injected at startup (see main.py)
_pipeline = None


def set_pipeline(pipeline) -> None:
    global _pipeline
    _pipeline = pipeline


def get_pipeline():
    if _pipeline is None:
        raise HTTPException(status_code=503, detail="Detection pipeline not initialised")
    return _pipeline


# ── Health ─────────────────────────────────────────────────────────────────────

@router.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "detection-engine",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── Stats ──────────────────────────────────────────────────────────────────────

@router.get("/stats", response_model=DetectionStats)
async def get_stats(db: AsyncSession = Depends(get_db)):
    pipeline = get_pipeline()

    # Total alerts
    total_alerts = (await db.execute(select(func.count()).select_from(Alert))).scalar() or 0
    open_alerts = (
        await db.execute(
            select(func.count()).select_from(Alert).where(Alert.status == AlertStatus.OPEN)
        )
    ).scalar() or 0
    suppressed = (
        await db.execute(
            select(func.count()).select_from(Alert).where(Alert.status == AlertStatus.SUPPRESSED)
        )
    ).scalar() or 0

    # Incidents
    total_incidents = (await db.execute(select(func.count()).select_from(Incident))).scalar() or 0
    open_incidents = (
        await db.execute(
            select(func.count()).select_from(Incident).where(
                Incident.status == IncidentStatus.OPEN
            )
        )
    ).scalar() or 0

    # Rules
    rules_loaded = pipeline.sigma.rule_count

    # ML status
    ml_trained = pipeline.ml.is_any_model_trained()

    # Alerts in last hour
    from datetime import timedelta
    one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    alerts_last_hour = (
        await db.execute(
            select(func.count()).select_from(Alert).where(Alert.created_at >= one_hour_ago)
        )
    ).scalar() or 0

    return DetectionStats(
        total_alerts=total_alerts,
        open_alerts=open_alerts,
        suppressed_alerts=suppressed,
        total_incidents=total_incidents,
        open_incidents=open_incidents,
        rules_loaded=rules_loaded,
        ml_model_trained=ml_trained,
        alerts_last_hour=alerts_last_hour,
    )


# ── On-demand event analysis ───────────────────────────────────────────────────

@router.post("/events/analyze")
async def analyze_event(
    event: dict[str, Any],
    db: AsyncSession = Depends(get_db),
):
    """Submit a single normalised event for immediate detection pipeline run."""
    pipeline = get_pipeline()
    alerts = await pipeline.process_event(event, db)
    return {
        "alerts_created": len(alerts),
        "alerts": alerts,
    }


# ── Rules ──────────────────────────────────────────────────────────────────────

@router.get("/rules", response_model=list[RuleRead])
async def list_rules(
    enabled: Optional[bool] = None,
    rule_type: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    q = select(DetectionRule)
    if enabled is not None:
        q = q.where(DetectionRule.enabled == enabled)
    if rule_type:
        q = q.where(DetectionRule.rule_type == rule_type)
    q = q.offset(skip).limit(limit).order_by(DetectionRule.created_at.desc())
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/rules/{rule_id}", response_model=RuleRead)
async def get_rule(rule_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(DetectionRule).where(DetectionRule.rule_id == rule_id)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    return rule


@router.patch("/rules/{rule_id}", response_model=RuleRead)
async def update_rule(
    rule_id: str,
    update: RuleUpdate,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(DetectionRule).where(DetectionRule.rule_id == rule_id)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

    if update.enabled is not None:
        rule.enabled = update.enabled
    if update.severity is not None:
        rule.severity = update.severity

    await db.flush()
    return rule


# ── Alerts ─────────────────────────────────────────────────────────────────────

@router.get("/alerts", response_model=list[AlertRead])
async def list_alerts(
    status: Optional[AlertStatus] = None,
    severity: Optional[Severity] = None,
    asset_id: Optional[str] = None,
    rule_id: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    q = select(Alert)
    if status:
        q = q.where(Alert.status == status)
    if severity:
        q = q.where(Alert.severity == severity)
    if asset_id:
        q = q.where(Alert.asset_id == asset_id)
    if rule_id:
        q = q.where(Alert.rule_id == rule_id)
    q = q.offset(skip).limit(limit).order_by(desc(Alert.created_at))
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/alerts/{alert_id}", response_model=AlertRead)
async def get_alert(alert_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/alerts/{alert_id}", response_model=AlertRead)
async def update_alert(
    alert_id: uuid.UUID,
    update: AlertUpdate,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if update.status is not None:
        alert.status = update.status

    await db.flush()
    return alert


# ── Incidents ──────────────────────────────────────────────────────────────────

@router.get("/incidents", response_model=list[IncidentRead])
async def list_incidents(
    status: Optional[IncidentStatus] = None,
    severity: Optional[Severity] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    q = select(Incident)
    if status:
        q = q.where(Incident.status == status)
    if severity:
        q = q.where(Incident.severity == severity)
    q = q.offset(skip).limit(limit).order_by(desc(Incident.created_at))
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/incidents/{incident_id}", response_model=IncidentRead)
async def get_incident(incident_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.patch("/incidents/{incident_id}", response_model=IncidentRead)
async def update_incident(
    incident_id: uuid.UUID,
    update: IncidentUpdate,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if update.status is not None:
        incident.status = update.status
    if update.description is not None:
        incident.description = update.description

    await db.flush()
    return incident


# ── ML Models ─────────────────────────────────────────────────────────────────

@router.get("/models")
async def get_model_status():
    pipeline = get_pipeline()
    return {
        "models": pipeline.ml.get_model_info(),
        "contamination": pipeline.ml.contamination,
        "min_samples": pipeline.ml.min_samples,
    }
