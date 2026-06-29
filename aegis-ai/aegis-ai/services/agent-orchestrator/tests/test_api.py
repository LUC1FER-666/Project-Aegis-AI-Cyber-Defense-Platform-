"""API route tests — mocked DB, no live PostgreSQL."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport


# ── App fixture with DB overridden ───────────────────────────────────────────

def _make_task(
    status: str = "pending_approval",
    severity: str = "high",
    playbook: str = "brute_force_response",
) -> MagicMock:
    from app.models import TaskStatus

    task = MagicMock()
    task.id = str(uuid.uuid4())
    task.incident_id = "inc-001"
    task.incident_title = "Test Incident"
    task.severity = severity
    task.status = TaskStatus(status)
    task.triage = {
        "urgency_score": 0.8,
        "attack_stage": "initial_access",
        "recommended_response_tier": "supervised",
        "summary": "Test",
        "key_indicators": ["k1"],
    }
    task.selected_playbook = playbook
    task.playbook_steps = [{"action_type": "block_ip", "target": "t", "parameters": {}}]
    task.actions_results = None
    task.approval_notes = None
    task.approved_by = None
    task.approved_at = None
    task.extra_data = {}
    task.created_at = datetime.now(tz=timezone.utc)
    task.updated_at = datetime.now(tz=timezone.utc)
    return task


@pytest.fixture
def app():
    """Return the FastAPI app with lifespan disabled."""
    from contextlib import asynccontextmanager
    from fastapi import FastAPI
    from app.api.routes import router

    @asynccontextmanager
    async def noop_lifespan(app):
        yield

    test_app = FastAPI(lifespan=noop_lifespan)
    test_app.include_router(router)
    return test_app


# ── /health ───────────────────────────────────────────────────────────────────

class TestHealth:
    @pytest.mark.asyncio
    async def test_health_returns_ok(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


# ── /api/v1/playbooks ─────────────────────────────────────────────────────────

class TestPlaybooksEndpoint:
    @pytest.mark.asyncio
    async def test_lists_all_five_playbooks(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/api/v1/playbooks")
        assert resp.status_code == 200
        names = [p["name"] for p in resp.json()]
        assert len(names) == 5
        assert "generic_investigation" in names

    @pytest.mark.asyncio
    async def test_playbook_has_required_fields(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/api/v1/playbooks")
        for pb in resp.json():
            assert "name" in pb
            assert "trigger_techniques" in pb
            assert "trigger_attack_stages" in pb
            assert "steps" in pb


# ── /api/v1/tasks ─────────────────────────────────────────────────────────────

class TestTasksEndpoints:
    def _mock_db_with_tasks(self, tasks: list):
        """Return a mock DB session that yields the given tasks on select."""
        from sqlalchemy.ext.asyncio import AsyncSession

        mock_db = AsyncMock(spec=AsyncSession)

        # scalar_one for count
        count_result = MagicMock()
        count_result.scalar_one = MagicMock(return_value=len(tasks))

        # scalars for task list
        list_result = MagicMock()
        list_result.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=tasks)))

        # scalar_one_or_none for single task lookup
        single_result = MagicMock()
        single_result.scalar_one_or_none = MagicMock(
            return_value=tasks[0] if tasks else None
        )

        mock_db.execute = AsyncMock(side_effect=[count_result, list_result])
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        mock_db.flush = AsyncMock()
        mock_db.add = MagicMock()
        mock_db.close = AsyncMock()
        mock_db.rollback = AsyncMock()

        return mock_db

    @pytest.mark.asyncio
    async def test_list_tasks_returns_200(self, app):
        tasks = [_make_task()]
        mock_db = self._mock_db_with_tasks(tasks)

        from app.database import get_db
        app.dependency_overrides[get_db] = lambda: mock_db

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/api/v1/tasks")

        app.dependency_overrides.clear()
        assert resp.status_code == 200
        data = resp.json()
        assert "tasks" in data
        assert "total" in data

    @pytest.mark.asyncio
    async def test_get_task_404_when_not_found(self, app):
        mock_db = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none = MagicMock(return_value=None)
        mock_db.execute = AsyncMock(return_value=result)
        mock_db.close = AsyncMock()
        mock_db.rollback = AsyncMock()

        from app.database import get_db
        app.dependency_overrides[get_db] = lambda: mock_db

        task_id = str(uuid.uuid4())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(f"/api/v1/tasks/{task_id}")

        app.dependency_overrides.clear()
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_get_task_actions_returns_empty_list(self, app):
        task = _make_task()
        mock_db = AsyncMock()

        task_result = MagicMock()
        task_result.scalar_one_or_none = MagicMock(return_value=task)
        logs_result = MagicMock()
        logs_result.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))

        mock_db.execute = AsyncMock(side_effect=[task_result, logs_result])
        mock_db.close = AsyncMock()
        mock_db.rollback = AsyncMock()

        from app.database import get_db
        app.dependency_overrides[get_db] = lambda: mock_db

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(f"/api/v1/tasks/{task.id}/actions")

        app.dependency_overrides.clear()
        assert resp.status_code == 200
        assert resp.json() == []


# ── Approve / Reject ──────────────────────────────────────────────────────────

class TestApproveReject:
    @pytest.mark.asyncio
    async def test_approve_wrong_status_returns_400(self, app):
        task = _make_task(status="completed")
        mock_db = AsyncMock()

        result = MagicMock()
        result.scalar_one_or_none = MagicMock(return_value=task)
        mock_db.execute = AsyncMock(return_value=result)
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        mock_db.close = AsyncMock()
        mock_db.rollback = AsyncMock()

        from app.database import get_db
        app.dependency_overrides[get_db] = lambda: mock_db

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.patch(
                f"/api/v1/tasks/{task.id}/approve",
                json={"notes": "ok", "approved_by": "analyst1"},
            )

        app.dependency_overrides.clear()
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_reject_sets_rejected_status(self, app):
        from app.models import TaskStatus

        task = _make_task(status="pending_approval")
        mock_db = AsyncMock()

        result = MagicMock()
        result.scalar_one_or_none = MagicMock(return_value=task)
        mock_db.execute = AsyncMock(return_value=result)
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock(side_effect=lambda t: None)
        mock_db.close = AsyncMock()
        mock_db.rollback = AsyncMock()

        from app.database import get_db
        app.dependency_overrides[get_db] = lambda: mock_db

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            with patch("app.kafka.publish", new_callable=AsyncMock):
                resp = await client.patch(
                    f"/api/v1/tasks/{task.id}/reject",
                    json={"notes": "not approved"},
                )

        app.dependency_overrides.clear()
        # Task object should have been mutated to rejected
        assert task.status == TaskStatus.REJECTED


# ── /api/v1/incidents/analyze ─────────────────────────────────────────────────

class TestAnalyzeEndpoint:
    @pytest.mark.asyncio
    async def test_analyze_incident_runs_pipeline(self, app):
        """End-to-end: analyze endpoint calls _run_and_store and returns task."""
        incident = {
            "id": "inc-e2e",
            "title": "E2E Test Incident",
            "severity": "critical",
            "mitre_techniques": ["T1059.001"],
            "asset_ids": ["asset-001"],
        }

        stored_task = _make_task(status="completed", severity="critical")
        stored_task.extra_data = incident

        async def mock_run_and_store(inc, db):
            return stored_task

        with patch("app.api.routes._run_and_store", new=mock_run_and_store):
            mock_db = AsyncMock()
            mock_db.commit = AsyncMock()
            mock_db.refresh = AsyncMock()
            mock_db.close = AsyncMock()
            mock_db.rollback = AsyncMock()

            from app.database import get_db
            app.dependency_overrides[get_db] = lambda: mock_db

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                resp = await client.post(
                    "/api/v1/incidents/analyze",
                    json={"incident": incident},
                )

            app.dependency_overrides.clear()

        assert resp.status_code == 200
        data = resp.json()
        assert "id" in data
        assert "status" in data

    @pytest.mark.asyncio
    async def test_analyze_invalid_body_returns_422(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/incidents/analyze",
                json={"wrong_key": "value"},
            )
        assert resp.status_code == 422


# ── /stats ────────────────────────────────────────────────────────────────────

class TestStatsEndpoint:
    @pytest.mark.asyncio
    async def test_stats_returns_expected_shape(self, app):
        mock_db = AsyncMock()

        # total_tasks
        r1 = MagicMock(); r1.scalar_one = MagicMock(return_value=5)
        # by_status
        r2 = MagicMock(); r2.fetchall = MagicMock(return_value=[])
        # by_playbook
        r3 = MagicMock(); r3.fetchall = MagicMock(return_value=[])
        # avg_ms
        r4 = MagicMock(); r4.scalar_one = MagicMock(return_value=123.0)
        # pending_count
        r5 = MagicMock(); r5.scalar_one = MagicMock(return_value=2)

        mock_db.execute = AsyncMock(side_effect=[r1, r2, r3, r4, r5])
        mock_db.close = AsyncMock()
        mock_db.rollback = AsyncMock()

        from app.database import get_db
        app.dependency_overrides[get_db] = lambda: mock_db

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/stats")

        app.dependency_overrides.clear()
        assert resp.status_code == 200
        data = resp.json()
        assert "total_tasks" in data
        assert "by_status" in data
        assert "pending_approval_count" in data
        assert data["total_tasks"] == 5
        assert data["pending_approval_count"] == 2
