"""
Shared domain models — Pydantic schemas used as API request/response types
and Kafka message payloads across all Aegis services.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# =============================================================================
# ENUMS
# =============================================================================

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AssetType(str, Enum):
    ENDPOINT = "endpoint"
    SERVER = "server"
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    CLOUD_VM = "cloud_vm"
    CONTAINER = "container"
    KUBERNETES_NODE = "kubernetes_node"
    DATABASE = "database"
    APPLICATION = "application"
    UNKNOWN = "unknown"


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class DetectionType(str, Enum):
    RULE = "rule"
    ML_ANOMALY = "ml_anomaly"
    AI_REASONING = "ai_reasoning"
    THREAT_INTEL = "threat_intel"
    BEHAVIORAL = "behavioral"


class ResponseActionType(str, Enum):
    KILL_PROCESS = "kill_process"
    QUARANTINE_ENDPOINT = "quarantine_endpoint"
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    DISABLE_USER = "disable_user"
    FORCE_PASSWORD_RESET = "force_password_reset"
    REVOKE_TOKENS = "revoke_tokens"
    CREATE_TICKET = "create_ticket"
    SEND_ALERT = "send_alert"
    ISOLATE_CONTAINER = "isolate_container"


class ResponseActionStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class PlatformMode(str, Enum):
    SIMULATION = "simulation"      # No real actions, log only
    APPROVAL = "approval"          # Requires human sign-off
    AUTONOMOUS = "autonomous"      # Lab/trusted env only


class UserRole(str, Enum):
    ADMIN = "admin"
    SOC_ANALYST = "soc_analyst"
    SOC_LEAD = "soc_lead"
    THREAT_HUNTER = "threat_hunter"
    EXECUTIVE = "executive"
    READ_ONLY = "read_only"


# =============================================================================
# BASE
# =============================================================================

class AegisBaseModel(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        use_enum_values=True,
    )


# =============================================================================
# KAFKA MESSAGE ENVELOPES
# All Kafka messages must use these wrappers for schema consistency.
# =============================================================================

class KafkaMessage(AegisBaseModel):
    """Standard envelope for all Kafka messages."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    topic: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source_service: str
    schema_version: str = "1.0"
    payload: dict[str, Any]


# =============================================================================
# ASSETS
# =============================================================================

class AssetBase(AegisBaseModel):
    hostname: str | None = None
    ip_address: str
    mac_address: str | None = None
    asset_type: AssetType = AssetType.UNKNOWN
    os_name: str | None = None
    os_version: str | None = None
    cloud_provider: str | None = None
    cloud_region: str | None = None
    criticality: int = Field(default=3, ge=1, le=4)  # 1=critical, 4=low
    tags: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AssetCreate(AssetBase):
    pass


class AssetRead(AssetBase):
    id: uuid.UUID
    first_seen: datetime
    last_seen: datetime
    is_active: bool


class AssetDiscoveredEvent(AegisBaseModel):
    """Kafka payload for aegis.assets.discovered"""
    asset: AssetRead
    discovery_method: str  # nmap, cloud_api, agent, manual
    scan_id: str | None = None


# =============================================================================
# DETECTIONS
# =============================================================================

class DetectionBase(AegisBaseModel):
    asset_id: uuid.UUID | None = None
    rule_id: str | None = None
    detection_type: DetectionType
    title: str
    description: str
    severity: Severity
    mitre_technique: str | None = None  # e.g. T1059.001
    confidence_score: float = Field(ge=0.0, le=100.0)
    evidence: dict[str, Any] = Field(default_factory=dict)


class DetectionRead(DetectionBase):
    id: uuid.UUID
    incident_id: uuid.UUID | None = None
    false_positive: bool
    created_at: datetime


class AlertEvent(AegisBaseModel):
    """Kafka payload for aegis.detections.alerts"""
    detection: DetectionRead
    raw_event_ids: list[str] = Field(default_factory=list)


# =============================================================================
# INCIDENTS
# =============================================================================

class IncidentBase(AegisBaseModel):
    title: str
    severity: Severity
    attack_stage: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    affected_asset_ids: list[uuid.UUID] = Field(default_factory=list)


class IncidentRead(IncidentBase):
    id: uuid.UUID
    status: IncidentStatus
    confidence_score: float | None = None
    risk_score: float | None = None
    root_cause: str | None = None
    attack_chain: list[dict[str, Any]] = Field(default_factory=list)
    business_impact: str | None = None
    assigned_to: str | None = None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None = None


# =============================================================================
# RESPONSE ACTIONS
# =============================================================================

class ResponseActionBase(AegisBaseModel):
    action_type: ResponseActionType
    target_asset_id: uuid.UUID | None = None
    target_identifier: str | None = None  # IP, domain, PID, username
    parameters: dict[str, Any] = Field(default_factory=dict)
    proposed_by: str  # agent name


class ResponseActionRead(ResponseActionBase):
    id: uuid.UUID
    incident_id: uuid.UUID
    status: ResponseActionStatus
    approved_by: str | None = None
    approved_at: datetime | None = None
    executed_at: datetime | None = None
    outcome: str | None = None
    rollback_available: bool
    created_at: datetime


# =============================================================================
# THREAT INTELLIGENCE
# =============================================================================

class ThreatIntelBase(AegisBaseModel):
    intel_type: str      # ioc, ttp, campaign, actor, malware
    source: str          # otx, virustotal, cisa, nvd
    indicator_type: str  # ip, domain, hash, url
    indicator_value: str
    confidence: str | None = None
    severity: Severity | None = None
    tags: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)


class ThreatIntelRead(ThreatIntelBase):
    id: uuid.UUID
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    expires_at: datetime | None = None
    created_at: datetime


# =============================================================================
# API RESPONSES
# =============================================================================

class PaginatedResponse(AegisBaseModel):
    """Standard paginated list response."""
    total: int
    page: int
    page_size: int
    items: list[Any]


class HealthResponse(AegisBaseModel):
    status: str
    service: str
    version: str
    environment: str
    checks: dict[str, str] = Field(default_factory=dict)


class ErrorResponse(AegisBaseModel):
    error: str
    detail: str | None = None
    request_id: str | None = None
