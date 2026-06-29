from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.models import ActionStatus, PredictionStatus


class ThreatPredictionOut(BaseModel):
    id: str
    prediction_id: str
    threat_type: str
    confidence: float
    affected_assets: Optional[list[str]] = None
    evidence_summary: str
    predicted_attack_vector: str
    recommended_actions: Optional[list[str]] = None
    status: PredictionStatus
    expires_at: datetime
    created_at: datetime
    model_config = {"from_attributes": True}


class PreemptiveActionOut(BaseModel):
    id: str
    prediction_id: str
    action_type: str
    target: str
    status: ActionStatus
    result_data: Optional[dict[str, Any]] = None
    confidence_trigger: float
    executed_at: datetime
    model_config = {"from_attributes": True}


class AttackNarrativeOut(BaseModel):
    id: str
    source_type: str
    source_id: str
    headline: str
    severity_assessment: str
    attack_timeline: Optional[list[str]] = None
    likely_objective: str
    immediate_actions: Optional[list[str]] = None
    technical_indicators: Optional[list[str]] = None
    confidence: float
    created_at: datetime
    model_config = {"from_attributes": True}


class SOCNotificationOut(BaseModel):
    id: str
    notification_type: str
    title: str
    body: str
    severity: str
    read: bool
    asset_ids: Optional[list[str]] = None
    evidence: Optional[dict[str, Any]] = None
    created_at: datetime
    model_config = {"from_attributes": True}


class GenerateNarrativeRequest(BaseModel):
    source_type: str = "manual"
    source_id: str = "manual"
    context: dict[str, Any] = Field(default_factory=dict)


class StatsResponse(BaseModel):
    active_predictions: int
    notifications_unread: int
    narratives_generated: int
    preemptive_actions_taken: int
    agent_status: str


class AgentStatusResponse(BaseModel):
    status: str
    current_threats: list[str]
    predictions: list[str]
    narratives: list[str]
    actions_taken: list[str]
    notifications_sent: list[str]
