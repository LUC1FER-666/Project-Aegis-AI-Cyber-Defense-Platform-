"""
Detection Engine — Database Models

NOTE: Avoid SQLAlchemy reserved column names:
- 'metadata' is reserved → use 'extra_data'
- 'type' is safe as a column but conflicts with Python builtins → use 'rule_type', 'alert_type'
"""
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Column, String, Float, Integer, DateTime, Boolean,
    Text, JSON, ForeignKey, Enum as SAEnum, Index
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.sql import func
import enum


class Base(DeclarativeBase):
    pass


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    SUPPRESSED = "suppressed"
    CLOSED = "closed"


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"


class DetectionRule(Base):
    """Persisted Sigma rule metadata (actual YAML on disk)."""
    __tablename__ = "detection_rules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_id = Column(String(255), unique=True, nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(SAEnum(Severity), nullable=False, default=Severity.MEDIUM)
    mitre_technique = Column(String(50), nullable=True)   # e.g. T1059.001
    mitre_tactic = Column(String(100), nullable=True)      # e.g. execution
    rule_type = Column(String(50), nullable=False, default="sigma")  # sigma | ml | composite
    enabled = Column(Boolean, nullable=False, default=True)
    false_positive_rate = Column(Float, nullable=False, default=0.0)
    hit_count = Column(Integer, nullable=False, default=0)
    extra_data = Column(JSON, nullable=True)               # raw YAML fields, tags, etc.
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    alerts = relationship("Alert", back_populates="rule", lazy="select")


class Alert(Base):
    """Individual detection hit before correlation."""
    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_id = Column(String(255), ForeignKey("detection_rules.rule_id"), nullable=False, index=True)
    asset_id = Column(String(255), nullable=True, index=True)
    severity = Column(SAEnum(Severity), nullable=False)
    status = Column(SAEnum(AlertStatus), nullable=False, default=AlertStatus.OPEN)

    # Detection details
    mitre_technique = Column(String(50), nullable=True)
    confidence_score = Column(Float, nullable=False)       # 0.0 – 1.0
    anomaly_score = Column(Float, nullable=True)           # from Isolation Forest
    llm_validated = Column(Boolean, nullable=True)         # None = not checked
    llm_reasoning = Column(Text, nullable=True)
    suppressed_by_llm = Column(Boolean, nullable=False, default=False)

    # Evidence payload — raw event fields that triggered the rule
    evidence = Column(JSON, nullable=False, default=dict)

    # Source event identifiers
    source_event_id = Column(String(255), nullable=True)
    source_log_type = Column(String(100), nullable=True)
    source_timestamp = Column(DateTime(timezone=True), nullable=True)

    # Correlation
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=True, index=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    rule = relationship("DetectionRule", back_populates="alerts")
    incident = relationship("Incident", back_populates="alerts")

    __table_args__ = (
        Index("ix_alerts_created_asset", "created_at", "asset_id"),
    )


class Incident(Base):
    """Correlated group of related alerts."""
    __tablename__ = "incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(SAEnum(Severity), nullable=False)
    status = Column(SAEnum(IncidentStatus), nullable=False, default=IncidentStatus.OPEN)

    # Attack context
    mitre_techniques = Column(JSON, nullable=False, default=list)   # list of technique IDs
    affected_assets = Column(JSON, nullable=False, default=list)    # list of asset IDs
    alert_count = Column(Integer, nullable=False, default=0)

    # Correlation metadata
    correlation_key = Column(String(255), nullable=True, index=True)  # grouping key used
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)

    extra_data = Column(JSON, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    alerts = relationship("Alert", back_populates="incident")


class AnomalyModel(Base):
    """Tracks ML model state per event category."""
    __tablename__ = "anomaly_models"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    model_key = Column(String(100), unique=True, nullable=False, index=True)  # e.g. "process", "network"
    sample_count = Column(Integer, nullable=False, default=0)
    is_trained = Column(Boolean, nullable=False, default=False)
    last_trained_at = Column(DateTime(timezone=True), nullable=True)
    model_version = Column(Integer, nullable=False, default=0)
    extra_data = Column(JSON, nullable=True)   # feature names, hyperparams, etc.
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
