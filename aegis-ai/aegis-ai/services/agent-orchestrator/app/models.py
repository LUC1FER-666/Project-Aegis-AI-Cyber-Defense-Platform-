import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum

from sqlalchemy import (
    Column, String, Float, Integer, DateTime, Text, JSON,
    ForeignKey, Enum as SAEnum
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()


class TaskStatus(str, PyEnum):
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REJECTED = "rejected"


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class AgentTask(Base):
    __tablename__ = "agent_tasks"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    incident_id = Column(String(255), nullable=False, index=True)
    incident_title = Column(String(1024), nullable=False)
    severity = Column(String(64), nullable=False)
    status = Column(
        SAEnum(TaskStatus, name="task_status_enum", create_type=True),
        nullable=False,
        default=TaskStatus.PENDING_APPROVAL,
        index=True,
    )
    triage = Column(JSON, nullable=True)
    selected_playbook = Column(String(255), nullable=True)
    playbook_steps = Column(JSON, nullable=True)
    actions_results = Column(JSON, nullable=True)
    approval_notes = Column(Text, nullable=True)
    approved_by = Column(String(255), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    extra_data = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_now)
    updated_at = Column(
        DateTime(timezone=True), nullable=False, default=_now, onupdate=_now
    )

    action_logs = relationship(
        "ActionLog", back_populates="task", cascade="all, delete-orphan"
    )


class ActionLog(Base):
    __tablename__ = "action_logs"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    task_id = Column(
        UUID(as_uuid=False),
        ForeignKey("agent_tasks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    action_type = Column(String(128), nullable=False)
    target = Column(String(512), nullable=False)
    status = Column(String(64), nullable=False)
    result_data = Column(JSON, nullable=True)
    duration_ms = Column(Integer, nullable=False, default=0)
    executed_at = Column(DateTime(timezone=True), nullable=False, default=_now)

    task = relationship("AgentTask", back_populates="action_logs")
