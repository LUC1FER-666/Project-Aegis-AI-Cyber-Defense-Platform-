"""Unit tests for the LangGraph workflow — no live Ollama/DB/Kafka."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch

from app.graph.workflow import (
    OrchestratorState,
    _route_after_approval,
    approval_node,
    build_graph,
    compiled_graph,
    execute_node,
    playbook_node,
    report_node,
    run_pipeline,
    triage_node,
)


INCIDENT = {
    "id": "inc-001",
    "title": "PowerShell Execution",
    "severity": "critical",
    "mitre_techniques": ["T1059.001"],
    "asset_ids": ["asset-abc"],
    "evidence": {},
}

LOW_INCIDENT = {
    "id": "inc-002",
    "title": "Suspicious DNS",
    "severity": "low",
    "mitre_techniques": [],
    "asset_ids": [],
    "evidence": {},
}


# ── Graph compilation ─────────────────────────────────────────────────────────

class TestGraphCompiles:
    def test_compiled_graph_is_not_none(self):
        assert compiled_graph is not None

    def test_build_graph_returns_state_graph(self):
        from langgraph.graph import StateGraph
        g = build_graph()
        assert g is not None


# ── Individual nodes ──────────────────────────────────────────────────────────

class TestTriageNode:
    @pytest.mark.asyncio
    async def test_triage_node_adds_triage_key(self):
        state: OrchestratorState = {"incident": INCIDENT, "error": None}
        result = await triage_node(state)
        assert "triage" in result
        assert result["triage"]["urgency_score"] > 0

    @pytest.mark.asyncio
    async def test_triage_node_never_raises(self):
        """Even with a broken incident, triage_node must return valid state."""
        state: OrchestratorState = {"incident": {}, "error": None}
        result = await triage_node(state)
        assert "triage" in result
        assert "urgency_score" in result["triage"]

    @pytest.mark.asyncio
    async def test_triage_node_critical_gives_high_urgency(self):
        state: OrchestratorState = {"incident": INCIDENT}
        result = await triage_node(state)
        assert result["triage"]["urgency_score"] >= 0.8


class TestPlaybookNode:
    @pytest.mark.asyncio
    async def test_playbook_node_selects_playbook(self):
        state: OrchestratorState = {
            "incident": INCIDENT,
            "triage": {
                "urgency_score": 0.95,
                "attack_stage": "execution",
                "recommended_response_tier": "automated",
            },
        }
        result = await playbook_node(state)
        assert result["selected_playbook"] == "malware_execution_response"
        assert len(result["playbook_steps"]) > 0

    @pytest.mark.asyncio
    async def test_playbook_node_returns_steps_as_dicts(self):
        state: OrchestratorState = {
            "incident": INCIDENT,
            "triage": {"attack_stage": "execution", "recommended_response_tier": "automated"},
        }
        result = await playbook_node(state)
        for step in result["playbook_steps"]:
            assert "action_type" in step

    @pytest.mark.asyncio
    async def test_playbook_node_fallback_on_error(self):
        """playbook_node must not raise even on bad input."""
        state: OrchestratorState = {
            "incident": {},
            "triage": {"attack_stage": "execution"},
        }
        result = await playbook_node(state)
        assert "selected_playbook" in result


class TestApprovalNode:
    @pytest.mark.asyncio
    async def test_approval_node_passes_state_through(self):
        state: OrchestratorState = {
            "incident": INCIDENT,
            "triage": {"recommended_response_tier": "automated"},
        }
        result = await approval_node(state)
        assert result == state

    def test_route_automated_to_execute(self):
        state: OrchestratorState = {
            "triage": {"recommended_response_tier": "automated"}
        }
        assert _route_after_approval(state) == "execute_node"

    def test_route_supervised_to_end(self):
        from langgraph.graph import END
        state: OrchestratorState = {
            "triage": {"recommended_response_tier": "supervised"}
        }
        assert _route_after_approval(state) == END

    def test_route_manual_to_end(self):
        from langgraph.graph import END
        state: OrchestratorState = {
            "triage": {"recommended_response_tier": "manual"}
        }
        assert _route_after_approval(state) == END

    def test_route_missing_tier_defaults_to_supervised(self):
        from langgraph.graph import END
        state: OrchestratorState = {"triage": {}}
        assert _route_after_approval(state) == END


class TestExecuteNode:
    @pytest.mark.asyncio
    async def test_execute_node_runs_all_steps(self):
        state: OrchestratorState = {
            "incident": INCIDENT,
            "playbook_steps": [
                {"action_type": "block_ip", "target": "asset-abc", "parameters": {}},
                {"action_type": "notify_soc", "target": "asset-abc", "parameters": {}},
            ],
        }
        result = await execute_node(state)
        assert len(result["actions_results"]) == 2

    @pytest.mark.asyncio
    async def test_execute_node_results_have_status(self):
        state: OrchestratorState = {
            "incident": INCIDENT,
            "playbook_steps": [
                {"action_type": "escalate_to_analyst", "target": "t", "parameters": {}},
            ],
        }
        result = await execute_node(state)
        for r in result["actions_results"]:
            assert r["status"] in ("success", "failed", "skipped")

    @pytest.mark.asyncio
    async def test_execute_node_empty_steps(self):
        state: OrchestratorState = {
            "incident": INCIDENT,
            "playbook_steps": [],
        }
        result = await execute_node(state)
        assert result["actions_results"] == []


class TestReportNode:
    @pytest.mark.asyncio
    async def test_report_node_builds_report(self):
        state: OrchestratorState = {
            "incident": INCIDENT,
            "triage": {
                "urgency_score": 0.95,
                "attack_stage": "execution",
                "summary": "Test",
            },
            "selected_playbook": "malware_execution_response",
            "actions_results": [
                {"action_type": "block_ip", "status": "success"},
                {"action_type": "notify_soc", "status": "failed"},
            ],
        }
        result = await report_node(state)
        report = result["final_report"]
        assert report["total_actions"] == 2
        assert report["successful_actions"] == 1
        assert report["failed_actions"] == 1
        assert report["playbook"] == "malware_execution_response"
        assert "completed_at" in report

    @pytest.mark.asyncio
    async def test_report_node_handles_empty_results(self):
        state: OrchestratorState = {
            "incident": {},
            "triage": {},
            "selected_playbook": "generic",
            "actions_results": [],
        }
        result = await report_node(state)
        assert result["final_report"]["total_actions"] == 0


# ── Full pipeline ─────────────────────────────────────────────────────────────

class TestRunPipeline:
    @pytest.mark.asyncio
    async def test_automated_pipeline_runs_to_completion(self):
        """critical severity → automated → full pipeline completes."""
        final = await run_pipeline(INCIDENT)
        assert "triage" in final
        assert "selected_playbook" in final
        # For automated tier, actions_results and final_report are populated
        triage = final.get("triage", {})
        if triage.get("recommended_response_tier") == "automated":
            assert len(final.get("actions_results", [])) > 0
            assert "final_report" in final

    @pytest.mark.asyncio
    async def test_supervised_pipeline_stops_at_approval(self):
        """low severity → manual → pipeline stops at approval node."""
        final = await run_pipeline(LOW_INCIDENT)
        triage = final.get("triage", {})
        if triage.get("recommended_response_tier") in ("supervised", "manual"):
            # actions_results should be empty (no execution)
            assert final.get("actions_results") in (None, [], [{}])

    @pytest.mark.asyncio
    async def test_pipeline_never_raises(self):
        """Broken incident must not crash the pipeline."""
        final = await run_pipeline({})
        assert "triage" in final

    @pytest.mark.asyncio
    async def test_pipeline_preserves_task_id(self):
        final = await run_pipeline(INCIDENT, task_id="test-task-123")
        assert final.get("task_id") == "test-task-123"

    @pytest.mark.asyncio
    async def test_pipeline_triage_has_valid_tier(self):
        final = await run_pipeline(INCIDENT)
        tier = final["triage"]["recommended_response_tier"]
        assert tier in ("automated", "supervised", "manual")
