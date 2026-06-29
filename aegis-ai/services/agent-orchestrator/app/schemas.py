from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.models import TaskStatus


# ── Triage ──────────────────────────────────────────────────────────────────

class TriageResult(BaseModel):
    urgency_score: float = Field(..., ge=0.0, le=1.0)
    attack_stage: str
    recommended_response_tier: str  # automated | supervised | manual
    summary: str
    key_indicators: list[str]


# ── Action / Playbook ────────────────────────────────────────────────────────

class ActionStepSchema(BaseModel):
    action_type: str
    target: Optional[str] = None
    parameters: dict[str, Any] = Field(default_factory=dict)


class PlaybookInfo(BaseModel):
    name: str
    trigger_techniques: list[str]
    trigger_attack_stages: list[str]
    steps: list[str]


# ── ActionLog ────────────────────────────────────────────────────────────────

class ActionLogOut(BaseModel):
    id: str
    task_id: str
    action_type: str
    target: str
    status: str
    result_data: Optional[dict[str, Any]] = None
    duration_ms: int
    executed_at: datetime

    model_config = {"from_attributes": True}


# ── AgentTask ────────────────────────────────────────────────────────────────

class AgentTaskOut(BaseModel):
    id: str
    incident_id: str
    incident_title: str
    severity: str
    status: TaskStatus
    triage: Optional[dict[str, Any]] = None
    selected_playbook: Optional[str] = None
    playbook_steps: Optional[list[Any]] = None
    actions_results: Optional[list[Any]] = None
    approval_notes: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    extra_data: Optional[dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ── Request bodies ───────────────────────────────────────────────────────────

class ApproveRequest(BaseModel):
    notes: str = ""
    approved_by: str


class RejectRequest(BaseModel):
    notes: str = ""


class AnalyzeIncidentRequest(BaseModel):
    incident: dict[str, Any]


# ── Pagination / list wrapper ────────────────────────────────────────────────

class TaskListResponse(BaseModel):
    tasks: list[AgentTaskOut]
    total: int
    page: int
    page_size: int


# ── Stats ────────────────────────────────────────────────────────────────────

class StatsResponse(BaseModel):
    total_tasks: int
    by_status: dict[str, int]
    by_playbook: dict[str, int]
    avg_execution_time_ms: float
    pending_approval_count: int
