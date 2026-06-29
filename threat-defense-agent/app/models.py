import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey,
    String, Text, Enum as SAEnum, JSON,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class PredictionStatus(str, PyEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"


class ActionStatus(str, PyEnum):
    EXECUTED = "executed"
    FAILED = "failed"
    SKIPPED = "skipped"


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class ThreatPrediction(Base):
    __tablename__ = "threat_predictions"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    prediction_id = Column(String(255), unique=True, nullable=False, index=True)
    threat_type = Column(String(128), nullable=False, index=True)
    confidence = Column(Float, nullable=False)
    affected_assets = Column(JSON, nullable=True)
    evidence_summary = Column(Text, nullable=False)
    predicted_attack_vector = Column(String(512), nullable=False)
    recommended_actions = Column(JSON, nullable=True)
    status = Column(
        SAEnum(PredictionStatus, name="prediction_status_enum", create_type=True),
        nullable=False,
        default=PredictionStatus.ACTIVE,
        index=True,
    )
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_now, onupdate=_now)

    preemptive_actions = relationship(
        "PreemptiveAction", back_populates="prediction", cascade="all, delete-orphan"
    )


class PreemptiveAction(Base):
    __tablename__ = "preemptive_actions"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    prediction_id = Column(String(255), ForeignKey("threat_predictions.prediction_id", ondelete="CASCADE"), nullable=False, index=True)
    action_type = Column(String(128), nullable=False)
    target = Column(String(512), nullable=False)
    status = Column(
        SAEnum(ActionStatus, name="action_status_enum", create_type=True),
        nullable=False,
        default=ActionStatus.EXECUTED,
    )
    result_data = Column(JSON, nullable=True)
    confidence_trigger = Column(Float, nullable=False)
    executed_at = Column(DateTime(timezone=True), nullable=False, default=_now)

    prediction = relationship("ThreatPrediction", back_populates="preemptive_actions")


class AttackNarrative(Base):
    __tablename__ = "attack_narratives"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    source_type = Column(String(64), nullable=False)  # incident / prediction / manual
    source_id = Column(String(255), nullable=False, index=True)
    headline = Column(String(1024), nullable=False)
    severity_assessment = Column(String(512), nullable=False)
    attack_timeline = Column(JSON, nullable=True)
    likely_objective = Column(Text, nullable=False)
    immediate_actions = Column(JSON, nullable=True)
    technical_indicators = Column(JSON, nullable=True)
    confidence = Column(Float, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_now)


class SOCNotification(Base):
    __tablename__ = "soc_notifications"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    notification_type = Column(String(128), nullable=False, index=True)
    title = Column(String(512), nullable=False)
    body = Column(Text, nullable=False)
    severity = Column(String(64), nullable=False)
    read = Column(Boolean, nullable=False, default=False)
    asset_ids = Column(JSON, nullable=True)
    evidence = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_now)
