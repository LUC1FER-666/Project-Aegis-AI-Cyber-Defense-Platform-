from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


def _now():
    return datetime.now(timezone.utc)


# ─── Timeline schemas ────────────────────────────────────────────────────────

class TimelineEventCreate(BaseModel):
    event_type: str
    severity: str = "info"
    title: str
    description: str = ""
    source_service: str
    source_id: str
    asset_ids: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    extra_data: dict[str, Any] | None = None
    timestamp: datetime = Field(default_factory=_now)


class TimelineEventOut(BaseModel):
    event_id: str
    event_type: str
    severity: str
    title: str
    description: str
    source_service: str
    source_id: str
    asset_ids: list[str]
    mitre_techniques: list[str]
    extra_data: dict[str, Any] | None
    timestamp: datetime
    created_at: datetime

    model_config = {"from_attributes": True}


class TimelineStats(BaseModel):
    total_events: int
    by_type: dict[str, int]
    by_severity: dict[str, int]
    events_last_hour: int
    events_last_24h: int


# ─── Graph schemas ────────────────────────────────────────────────────────────

class GraphNode(BaseModel):
    id: str
    type: str  # Asset | Alert | Incident | Technique | AgentTask
    label: str
    severity: str = "info"
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    type: str
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphStats(BaseModel):
    node_count: int
    edge_count: int


class GraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    stats: GraphStats
    warning: str | None = None
