"""
Detection Engine — Pydantic Schemas
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, ConfigDict

from app.models import Severity, AlertStatus, IncidentStatus


# ── Rule schemas ──────────────────────────────────────────────────────────────

class RuleBase(BaseModel):
    rule_id: str
    title: str
    description: Optional[str] = None
    severity: Severity = Severity.MEDIUM
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    rule_type: str = "sigma"
    enabled: bool = True


class RuleRead(RuleBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    false_positive_rate: float
    hit_count: int
    extra_data: Optional[dict[str, Any]] = None
    created_at: datetime
    updated_at: Optional[datetime] = None


class RuleUpdate(BaseModel):
    enabled: Optional[bool] = None
    severity: Optional[Severity] = None


# ── Alert schemas ─────────────────────────────────────────────────────────────

class AlertBase(BaseModel):
    rule_id: str
    asset_id: Optional[str] = None
    severity: Severity
    mitre_technique: Optional[str] = None
    confidence_score: float = Field(ge=0.0, le=1.0)
    evidence: dict[str, Any] = Field(default_factory=dict)
    source_event_id: Optional[str] = None
    source_log_type: Optional[str] = None
    source_timestamp: Optional[datetime] = None


class AlertRead(AlertBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    status: AlertStatus
    anomaly_score: Optional[float] = None
    llm_validated: Optional[bool] = None
    llm_reasoning: Optional[str] = None
    suppressed_by_llm: bool
    incident_id: Optional[uuid.UUID] = None
    created_at: datetime
    updated_at: Optional[datetime] = None


class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None


# ── Incident schemas ──────────────────────────────────────────────────────────

class IncidentBase(BaseModel):
    title: str
    description: Optional[str] = None
    severity: Severity
    mitre_techniques: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)


class IncidentRead(IncidentBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    status: IncidentStatus
    alert_count: int
    correlation_key: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    extra_data: Optional[dict[str, Any]] = None
    created_at: datetime
    updated_at: Optional[datetime] = None


class IncidentUpdate(BaseModel):
    status: Optional[IncidentStatus] = None
    description: Optional[str] = None


# ── Detection event (internal, published to Kafka) ────────────────────────────

class DetectionEvent(BaseModel):
    """Schema for aegis.detections.alerts Kafka topic."""
    alert_id: str
    rule_id: str
    asset_id: Optional[str]
    severity: str
    mitre_technique: Optional[str]
    confidence_score: float
    evidence: dict[str, Any]
    source_event_id: Optional[str]
    timestamp: str


class IncidentEvent(BaseModel):
    """Schema for aegis.incidents.created Kafka topic."""
    incident_id: str
    title: str
    severity: str
    mitre_techniques: list[str]
    affected_assets: list[str]
    alert_count: int
    first_seen: str
    last_seen: str
    timestamp: str


# ── Stats ─────────────────────────────────────────────────────────────────────

class DetectionStats(BaseModel):
    total_alerts: int
    open_alerts: int
    suppressed_alerts: int
    total_incidents: int
    open_incidents: int
    rules_loaded: int
    ml_model_trained: bool
    alerts_last_hour: int
