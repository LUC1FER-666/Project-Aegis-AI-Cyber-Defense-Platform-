"""Unit tests for the LangGraph defense agent — no live services."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch

from app.graph.defense_agent import (
    DefenseAgentState,
    analyze_threat_patterns,
    assess_asset_risk,
    build_defense_graph,
    compiled_defense_graph,
    execute_preemptive_action,
    generate_narrative,
    run_defense_agent,
    send_notification,
)
from datetime import datetime, timedelta, timezone


def _ts(offset_seconds: int = 0) -> str:
    return (datetime.now(tz=timezone.utc) - timedelta(seconds=abs(offset_seconds))).isoformat()


EVENTS = [
    # Brute force — 3 failures from same IP
    {"category": "auth", "auth_result": "failure", "src_ip": "10.0.0.1", "asset_id": "host-01", "timestamp": _ts(10)},
    {"category": "auth", "auth_result": "failure", "src_ip": "10.0.0.1", "asset_id": "host-01", "timestamp": _ts(20)},
    {"category": "auth", "auth_result": "failure", "src_ip": "10.0.0.1", "asset_id": "host-01", "timestamp": _ts(30)},
]

INCIDENTS = [
    {
        "incident_id": "inc-001",
        "title": "Test Incident",
        "severity": "high",
        "affected_assets": ["host-01"],
        "alert_count": 3,
        "mitre_techniques": ["T1110"],
    }
]


class TestGraphCompiles:
    def test_compiled_graph_not_none(self):
        assert compiled_defense_graph is not None

    def test_build_defense_graph_returns_graph(self):
        g = build_defense_graph()
        assert g is not None


class TestAnalyzeThreatPatterns:
    @pytest.mark.asyncio
    async def test_finds_brute_force_in_events(self):
        state: DefenseAgentState = {"events": EVENTS, "incidents": [], "predictions": [], "current_threats": []}
        result = await analyze_threat_patterns(state)
        types = [p["threat_type"] for p in result.get("predictions", [])]
        assert "brute_force_imminent" in types

    @pytest.mark.asyncio
    async def test_adds_incident_threats(self):
        state: DefenseAgentState = {"events": [], "incidents": INCIDENTS, "predictions": [], "current_threats": []}
        result = await analyze_threat_patterns(state)
        assert len(result.get("current_threats", [])) > 0

    @pytest.mark.asyncio
    async def test_empty_events_no_predictions(self):
        state: DefenseAgentState = {"events": [], "incidents": [], "predictions": [], "current_threats": []}
        result = await analyze_threat_patterns(state)
        assert result.get("predictions") == []

    @pytest.mark.asyncio
    async def test_preserves_existing_state_keys(self):
        state: DefenseAgentState = {
            "events": EVENTS, "incidents": [], "predictions": [],
            "current_threats": [], "narratives": [], "actions_taken": [],
            "notifications_sent": [], "error": None,
        }
        result = await analyze_threat_patterns(state)
        assert "narratives" in result
        assert result["error"] is None


class TestAssessAssetRisk:
    @pytest.mark.asyncio
    async def test_runs_without_crash(self):
        state: DefenseAgentState = {
            "events": [], "incidents": INCIDENTS,
            "predictions": [{"threat_type": "brute_force_imminent", "confidence": 0.85, "affected_assets": ["host-01"]}],
            "current_threats": [], "narratives": [], "actions_taken": [],
            "notifications_sent": [], "error": None,
        }
        result = await assess_asset_risk(state)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_empty_state_no_crash(self):
        state: DefenseAgentState = {"events": [], "incidents": [], "predictions": [], "current_threats": []}
        result = await assess_asset_risk(state)
        assert isinstance(result, dict)


class TestExecutePreemptiveAction:
    @pytest.mark.asyncio
    async def test_executes_actions_above_threshold(self):
        with patch("app.agents.preemptive.kafka.publish", new_callable=AsyncMock, return_value=True):
            state: DefenseAgentState = {
                "events": [], "incidents": [],
                "predictions": [{
                    "prediction_id": "pred-001",
                    "threat_type": "brute_force_imminent",
                    "confidence": 0.85,
                    "affected_assets": ["host-01"],
                    "evidence_summary": "Test evidence from 10.0.0.1",
                    "recommended_actions": ["rate_limit_ip"],
                }],
                "current_threats": [], "narratives": [], "actions_taken": [],
                "notifications_sent": [], "error": None,
            }
            result = await execute_preemptive_action(state)
            assert len(result.get("actions_taken", [])) > 0

    @pytest.mark.asyncio
    async def test_skips_actions_below_threshold(self):
        with patch("app.graph.defense_agent.get_settings") as mock_settings:
            mock_settings.return_value.prediction_confidence_threshold = 0.95
            state: DefenseAgentState = {
                "events": [], "incidents": [],
                "predictions": [{
                    "prediction_id": "pred-low",
                    "threat_type": "brute_force_imminent",
                    "confidence": 0.50,  # below threshold
                    "affected_assets": [],
                    "evidence_summary": "Low confidence",
                    "recommended_actions": [],
                }],
                "current_threats": [], "narratives": [], "actions_taken": [],
                "notifications_sent": [], "error": None,
            }
            result = await execute_preemptive_action(state)
            assert result.get("actions_taken") == []

    @pytest.mark.asyncio
    async def test_empty_predictions_no_actions(self):
        state: DefenseAgentState = {
            "events": [], "incidents": [], "predictions": [],
            "current_threats": [], "narratives": [], "actions_taken": [],
            "notifications_sent": [], "error": None,
        }
        result = await execute_preemptive_action(state)
        assert result.get("actions_taken") == []


class TestGenerateNarrative:
    @pytest.mark.asyncio
    async def test_generates_narrative_for_high_confidence_prediction(self):
        state: DefenseAgentState = {
            "events": [], "incidents": [],
            "predictions": [{
                "prediction_id": "pred-001",
                "threat_type": "brute_force_imminent",
                "confidence": 0.85,
                "affected_assets": ["host-01"],
                "evidence_summary": "Test evidence",
            }],
            "current_threats": [], "narratives": [], "actions_taken": [],
            "notifications_sent": [], "error": None,
        }
        result = await generate_narrative(state)
        assert len(result.get("narratives", [])) > 0

    @pytest.mark.asyncio
    async def test_generates_narrative_for_incidents(self):
        state: DefenseAgentState = {
            "events": [], "incidents": INCIDENTS,
            "predictions": [],
            "current_threats": [], "narratives": [], "actions_taken": [],
            "notifications_sent": [], "error": None,
        }
        result = await generate_narrative(state)
        assert len(result.get("narratives", [])) > 0

    @pytest.mark.asyncio
    async def test_skips_low_confidence_predictions(self):
        state: DefenseAgentState = {
            "events": [], "incidents": [],
            "predictions": [{
                "prediction_id": "pred-low",
                "threat_type": "brute_force_imminent",
                "confidence": 0.70,  # below 0.80 threshold
                "affected_assets": [],
                "evidence_summary": "Low confidence",
            }],
            "current_threats": [], "narratives": [], "actions_taken": [],
            "notifications_sent": [], "error": None,
        }
        result = await generate_narrative(state)
        assert result.get("narratives") == []


class TestSendNotification:
    @pytest.mark.asyncio
    async def test_broadcasts_prediction_notifications(self):
        broadcast_calls = []

        async def mock_broadcast(notif):
            broadcast_calls.append(notif)

        with patch("app.graph.defense_agent.broadcast", side_effect=mock_broadcast):
            state: DefenseAgentState = {
                "events": [], "incidents": [],
                "predictions": [{
                    "prediction_id": "pred-001",
                    "threat_type": "brute_force_imminent",
                    "confidence": 0.85,
                    "affected_assets": ["host-01"],
                    "evidence_summary": "Test",
                    "recommended_actions": [],
                }],
                "current_threats": [], "narratives": [], "actions_taken": [],
                "notifications_sent": [], "error": None,
            }
            result = await send_notification(state)

        assert len(broadcast_calls) > 0
        assert len(result.get("notifications_sent", [])) > 0

    @pytest.mark.asyncio
    async def test_no_notifications_for_empty_state(self):
        async def mock_broadcast(notif):
            pass

        with patch("app.graph.defense_agent.broadcast", side_effect=mock_broadcast):
            state: DefenseAgentState = {
                "events": [], "incidents": [], "predictions": [],
                "current_threats": [], "narratives": [], "actions_taken": [],
                "notifications_sent": [], "error": None,
            }
            result = await send_notification(state)

        assert result.get("notifications_sent") == []


class TestRunDefenseAgent:
    @pytest.mark.asyncio
    async def test_pipeline_completes_with_events(self):
        with patch("app.agents.preemptive.kafka.publish", new_callable=AsyncMock, return_value=True):
            with patch("app.graph.defense_agent.broadcast", new_callable=AsyncMock):
                final = await run_defense_agent(events=EVENTS, incidents=[])

        assert "predictions" in final
        assert "narratives" in final
        assert "actions_taken" in final
        assert "notifications_sent" in final
        assert final.get("completed_at") is not None

    @pytest.mark.asyncio
    async def test_pipeline_never_raises_on_empty_input(self):
        with patch("app.graph.defense_agent.broadcast", new_callable=AsyncMock):
            final = await run_defense_agent(events=[], incidents=[])
        assert isinstance(final, dict)

    @pytest.mark.asyncio
    async def test_pipeline_preserves_task_id_equivalent(self):
        with patch("app.graph.defense_agent.broadcast", new_callable=AsyncMock):
            final = await run_defense_agent(events=[], incidents=INCIDENTS)
        assert "completed_at" in final

    @pytest.mark.asyncio
    async def test_brute_force_events_trigger_predictions(self):
        with patch("app.agents.preemptive.kafka.publish", new_callable=AsyncMock, return_value=True):
            with patch("app.graph.defense_agent.broadcast", new_callable=AsyncMock):
                final = await run_defense_agent(events=EVENTS)

        types = [p["threat_type"] for p in (final.get("predictions") or [])]
        assert "brute_force_imminent" in types
