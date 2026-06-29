"""
Agent Orchestrator API routes.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import kafka
from app.agents.playbooks import PlaybookEngine
from app.database import get_db
from app.graph.workflow import run_pipeline
from app.models import ActionLog, AgentTask, TaskStatus
from app.schemas import (
    ActionLogOut,
    AgentTaskOut,
    AnalyzeIncidentRequest,
    ApproveRequest,
    RejectRequest,
    StatsResponse,
    TaskListResponse,
)

router = APIRouter()
logger = logging.getLogger(__name__)


# ── Helper: load task or 404 ─────────────────────────────────────────────────

async def _get_task_or_404(task_id: str, db: AsyncSession) -> AgentTask:
    result = await db.execute(select(AgentTask).where(AgentTask.id == task_id))
    task = result.scalar_one_or_none()
    if task is None:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")
    return task


# ── Helper: persist action logs ──────────────────────────────────────────────

async def _save_action_logs(
    task_id: str, results: list[dict[str, Any]], db: AsyncSession
) -> None:
    for r in results:
        log = ActionLog(
            task_id=task_id,
            action_type=r.get("action_type", "unknown"),
            target=r.get("target", ""),
            status=r.get("status", "unknown"),
            result_data=r.get("result_data"),
            duration_ms=r.get("duration_ms", 0),
            executed_at=datetime.fromisoformat(
                r.get("executed_at", datetime.now(tz=timezone.utc).isoformat())
            ),
        )
        db.add(log)


# ── Core pipeline runner (shared by analyze endpoint + Kafka consumer) ───────

async def _run_and_store(incident: dict[str, Any], db: AsyncSession) -> AgentTask:
    """
    Run the full agent pipeline and store results in the database.
    - automated tier → execute immediately, status=completed
    - supervised/manual → status=pending_approval, publish to aegis.response.proposed
    """
    # Initial task record
    task = AgentTask(
        incident_id=str(incident.get("id") or incident.get("incident_id") or "unknown"),
        incident_title=str(
            incident.get("title") or incident.get("incident_title") or "Unknown Incident"
        ),
        severity=str(incident.get("severity") or "medium"),
        status=TaskStatus.PENDING_APPROVAL,
    )
    db.add(task)
    await db.flush()  # get task.id

    # Run triage + playbook selection
    from app.graph.workflow import (
        playbook_node,
        triage_node,
    )

    initial = {
        "incident": incident,
        "triage": {},
        "selected_playbook": "",
        "playbook_steps": [],
        "task_id": task.id,
        "actions_results": [],
        "final_report": {},
        "error": None,
    }

    state = await triage_node(initial)
    state = await playbook_node(state)

    triage = state.get("triage") or {}
    tier = triage.get("recommended_response_tier", "supervised")

    task.triage = triage
    task.selected_playbook = state.get("selected_playbook")
    task.playbook_steps = state.get("playbook_steps")

    if tier == "automated":
        task.status = TaskStatus.EXECUTING
        await db.flush()

        from app.graph.workflow import execute_node, report_node

        state = await execute_node(state)
        state = await report_node(state)

        task.actions_results = state.get("actions_results")
        task.status = TaskStatus.COMPLETED

        if state.get("actions_results"):
            await _save_action_logs(task.id, state["actions_results"], db)

        await kafka.publish(
            "aegis.agents.results",
            {"task_id": task.id, "final_report": state.get("final_report")},
            key=task.id,
        )

    else:
        # supervised / manual → pending human approval
        task.status = TaskStatus.PENDING_APPROVAL
        await kafka.publish(
            "aegis.response.proposed",
            {
                "task_id": task.id,
                "incident_id": task.incident_id,
                "tier": tier,
                "playbook": task.selected_playbook,
                "triage": triage,
            },
            key=task.id,
        )

    await db.commit()
    await db.refresh(task)
    return task


# ── Routes ───────────────────────────────────────────────────────────────────

@router.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "service": "agent-orchestrator"}


@router.get("/stats", response_model=StatsResponse)
async def get_stats(db: AsyncSession = Depends(get_db)) -> StatsResponse:
    total_result = await db.execute(select(func.count(AgentTask.id)))
    total_tasks = total_result.scalar_one() or 0

    # by_status
    status_rows = await db.execute(
        select(AgentTask.status, func.count(AgentTask.id)).group_by(AgentTask.status)
    )
    by_status = {row[0].value: row[1] for row in status_rows.fetchall()}

    # by_playbook
    pb_rows = await db.execute(
        select(AgentTask.selected_playbook, func.count(AgentTask.id))
        .where(AgentTask.selected_playbook.isnot(None))
        .group_by(AgentTask.selected_playbook)
    )
    by_playbook = {row[0]: row[1] for row in pb_rows.fetchall() if row[0]}

    # avg execution time (sum of all action duration_ms)
    avg_ms_result = await db.execute(select(func.avg(ActionLog.duration_ms)))
    avg_ms = float(avg_ms_result.scalar_one() or 0.0)

    # pending approval count
    pending_result = await db.execute(
        select(func.count(AgentTask.id)).where(
            AgentTask.status == TaskStatus.PENDING_APPROVAL
        )
    )
    pending_count = pending_result.scalar_one() or 0

    return StatsResponse(
        total_tasks=total_tasks,
        by_status=by_status,
        by_playbook=by_playbook,
        avg_execution_time_ms=avg_ms,
        pending_approval_count=pending_count,
    )


@router.get("/api/v1/tasks", response_model=TaskListResponse)
async def list_tasks(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> TaskListResponse:
    stmt = select(AgentTask)

    if status:
        try:
            status_enum = TaskStatus(status)
            stmt = stmt.where(AgentTask.status == status_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

    if severity:
        stmt = stmt.where(AgentTask.severity == severity)

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total_result = await db.execute(count_stmt)
    total = total_result.scalar_one() or 0

    stmt = stmt.order_by(AgentTask.created_at.desc())
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)

    rows = await db.execute(stmt)
    tasks = rows.scalars().all()

    return TaskListResponse(
        tasks=[AgentTaskOut.model_validate(t) for t in tasks],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/api/v1/tasks/{task_id}", response_model=AgentTaskOut)
async def get_task(task_id: str, db: AsyncSession = Depends(get_db)) -> AgentTaskOut:
    task = await _get_task_or_404(task_id, db)
    return AgentTaskOut.model_validate(task)


@router.get("/api/v1/tasks/{task_id}/actions", response_model=list[ActionLogOut])
async def get_task_actions(
    task_id: str, db: AsyncSession = Depends(get_db)
) -> list[ActionLogOut]:
    await _get_task_or_404(task_id, db)
    rows = await db.execute(
        select(ActionLog)
        .where(ActionLog.task_id == task_id)
        .order_by(ActionLog.executed_at)
    )
    logs = rows.scalars().all()
    return [ActionLogOut.model_validate(lg) for lg in logs]


@router.patch("/api/v1/tasks/{task_id}/approve", response_model=AgentTaskOut)
async def approve_task(
    task_id: str, body: ApproveRequest, db: AsyncSession = Depends(get_db)
) -> AgentTaskOut:
    task = await _get_task_or_404(task_id, db)

    if task.status != TaskStatus.PENDING_APPROVAL:
        raise HTTPException(
            status_code=400,
            detail=f"Task is not pending approval (status={task.status.value})",
        )

    task.status = TaskStatus.APPROVED
    task.approval_notes = body.notes
    task.approved_by = body.approved_by
    task.approved_at = datetime.now(tz=timezone.utc)
    await db.commit()
    await db.refresh(task)

    # Trigger execution asynchronously (best-effort)
    try:
        await _execute_approved_task(task, db)
    except Exception as exc:
        logger.error("Auto-execution after approval failed: %s", exc)

    return AgentTaskOut.model_validate(task)


@router.patch("/api/v1/tasks/{task_id}/reject", response_model=AgentTaskOut)
async def reject_task(
    task_id: str, body: RejectRequest, db: AsyncSession = Depends(get_db)
) -> AgentTaskOut:
    task = await _get_task_or_404(task_id, db)

    if task.status not in (TaskStatus.PENDING_APPROVAL, TaskStatus.APPROVED):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot reject task with status={task.status.value}",
        )

    task.status = TaskStatus.REJECTED
    task.approval_notes = body.notes
    await db.commit()

    await kafka.publish(
        "aegis.response.proposed",
        {"task_id": task.id, "action": "cancelled", "reason": body.notes},
        key=task.id,
    )

    await db.refresh(task)
    return AgentTaskOut.model_validate(task)


@router.post("/api/v1/tasks/{task_id}/execute", response_model=AgentTaskOut)
async def execute_task(
    task_id: str, db: AsyncSession = Depends(get_db)
) -> AgentTaskOut:
    """Manually trigger execution of an approved task."""
    task = await _get_task_or_404(task_id, db)

    if task.status != TaskStatus.APPROVED:
        raise HTTPException(
            status_code=400,
            detail=f"Task must be in approved status (status={task.status.value})",
        )

    await _execute_approved_task(task, db)
    await db.refresh(task)
    return AgentTaskOut.model_validate(task)


async def _execute_approved_task(task: AgentTask, db: AsyncSession) -> None:
    """Run the executor for an approved task and update the DB record."""
    from app.graph.workflow import execute_node, report_node

    incident = task.extra_data or {}
    # Reconstruct state from stored task data
    state = {
        "incident": incident,
        "triage": task.triage or {},
        "selected_playbook": task.selected_playbook or "",
        "playbook_steps": task.playbook_steps or [],
        "task_id": task.id,
        "actions_results": [],
        "final_report": {},
        "error": None,
    }

    task.status = TaskStatus.EXECUTING
    await db.commit()

    try:
        state = await execute_node(state)
        state = await report_node(state)

        task.actions_results = state.get("actions_results")
        task.status = TaskStatus.COMPLETED

        if state.get("actions_results"):
            await _save_action_logs(task.id, state["actions_results"], db)

        await kafka.publish(
            "aegis.agents.results",
            {"task_id": task.id, "final_report": state.get("final_report")},
            key=task.id,
        )

    except Exception as exc:
        logger.error("Task execution failed for %s: %s", task.id, exc)
        task.status = TaskStatus.FAILED
        task.extra_data = (task.extra_data or {}) | {"execution_error": str(exc)}

    await db.commit()


@router.post("/api/v1/incidents/analyze", response_model=AgentTaskOut)
async def analyze_incident(
    body: AnalyzeIncidentRequest, db: AsyncSession = Depends(get_db)
) -> AgentTaskOut:
    """
    Submit an incident dict directly, run the full pipeline, return task.
    Primarily for testing without Kafka.
    """
    incident = body.incident
    # Store raw incident in extra_data for later execution if approval needed
    incident_id = str(
        incident.get("id") or incident.get("incident_id") or "manual"
    )

    # We need to pass incident through to executor, so store it in extra_data
    task = await _run_and_store(incident, db)
    # Patch extra_data with full incident for deferred execution
    task.extra_data = incident
    await db.commit()
    await db.refresh(task)

    return AgentTaskOut.model_validate(task)


@router.get("/api/v1/playbooks")
async def list_playbooks() -> list[dict[str, Any]]:
    engine = PlaybookEngine()
    return engine.list_playbooks()
