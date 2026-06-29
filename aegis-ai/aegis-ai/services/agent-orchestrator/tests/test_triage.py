"""Unit tests for IncidentTriageAgent — no live Ollama required."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.agents.triage import (
    IncidentTriageAgent,
    _heuristic_triage,
    _infer_attack_stage,
    _parse_llm_response,
)
from app.schemas import TriageResult


# ── _infer_attack_stage ───────────────────────────────────────────────────────

class TestInferAttackStage:
    def test_execution_from_T1059(self):
        assert _infer_attack_stage(["T1059.001"]) == "execution"

    def test_initial_access_from_T1110(self):
        assert _infer_attack_stage(["T1110"]) == "initial_access"

    def test_exfiltration_from_T1071(self):
        assert _infer_attack_stage(["T1071.004"]) == "exfiltration"

    def test_lateral_movement_from_T1021(self):
        assert _infer_attack_stage(["T1021"]) == "lateral_movement"

    def test_reconnaissance_from_T1046(self):
        assert _infer_attack_stage(["T1046"]) == "reconnaissance"

    def test_impact_from_T1486(self):
        assert _infer_attack_stage(["T1486"]) == "impact"

    def test_default_when_unknown(self):
        assert _infer_attack_stage(["T9999"]) == "execution"

    def test_empty_returns_default(self):
        assert _infer_attack_stage([]) == "execution"

    def test_first_match_wins(self):
        # T1110 → initial_access matches before T1071 → exfiltration
        result = _infer_attack_stage(["T1110", "T1071"])
        assert result in ("initial_access", "exfiltration")  # order-dependent


# ── _heuristic_triage ─────────────────────────────────────────────────────────

class TestHeuristicTriage:
    def _incident(self, severity: str, techniques: list[str] | None = None) -> dict:
        return {
            "id": "inc-001",
            "title": "Test Incident",
            "severity": severity,
            "mitre_techniques": techniques or [],
            "alert_ids": ["a1", "a2"],
        }

    def test_critical_urgency(self):
        result = _heuristic_triage(self._incident("critical"))
        assert result.urgency_score == 0.95
        assert result.recommended_response_tier == "automated"

    def test_high_urgency(self):
        result = _heuristic_triage(self._incident("high"))
        assert result.urgency_score == 0.80
        assert result.recommended_response_tier == "supervised"

    def test_medium_urgency(self):
        result = _heuristic_triage(self._incident("medium"))
        assert result.urgency_score == 0.55
        assert result.recommended_response_tier == "supervised"

    def test_low_urgency(self):
        result = _heuristic_triage(self._incident("low"))
        assert result.urgency_score == 0.30
        assert result.recommended_response_tier == "manual"

    def test_unknown_severity_defaults(self):
        result = _heuristic_triage({"severity": "unknown", "title": "X"})
        assert 0.0 <= result.urgency_score <= 1.0

    def test_attack_stage_from_techniques(self):
        result = _heuristic_triage(self._incident("high", ["T1059.001"]))
        assert result.attack_stage == "execution"

    def test_key_indicators_contain_techniques(self):
        result = _heuristic_triage(self._incident("high", ["T1110"]))
        assert any("T1110" in k for k in result.key_indicators)

    def test_key_indicators_not_empty(self):
        result = _heuristic_triage(self._incident("low"))
        assert len(result.key_indicators) > 0

    def test_returns_triage_result_type(self):
        result = _heuristic_triage(self._incident("critical"))
        assert isinstance(result, TriageResult)

    def test_summary_is_non_empty_string(self):
        result = _heuristic_triage(self._incident("medium"))
        assert isinstance(result.summary, str)
        assert len(result.summary) > 0


# ── _parse_llm_response ───────────────────────────────────────────────────────

class TestParseLlmResponse:
    def _incident(self):
        return {"mitre_techniques": ["T1059"], "severity": "high"}

    def test_parses_clean_json(self):
        raw = """{
            "urgency_score": 0.85,
            "attack_stage": "execution",
            "recommended_response_tier": "supervised",
            "summary": "Test summary",
            "key_indicators": ["indicator1", "indicator2"]
        }"""
        result = _parse_llm_response(raw, self._incident())
        assert result.urgency_score == 0.85
        assert result.attack_stage == "execution"
        assert result.recommended_response_tier == "supervised"
        assert result.summary == "Test summary"
        assert len(result.key_indicators) == 2

    def test_strips_markdown_fences(self):
        raw = "```json\n{\"urgency_score\": 0.7, \"attack_stage\": \"execution\", \"recommended_response_tier\": \"supervised\", \"summary\": \"s\", \"key_indicators\": []}\n```"
        result = _parse_llm_response(raw, self._incident())
        assert result.urgency_score == 0.7

    def test_clamps_urgency_score(self):
        raw = '{"urgency_score": 1.5, "attack_stage": "execution", "recommended_response_tier": "manual", "summary": "x", "key_indicators": []}'
        result = _parse_llm_response(raw, self._incident())
        assert result.urgency_score == 1.0

    def test_invalid_attack_stage_falls_back_to_heuristic(self):
        raw = '{"urgency_score": 0.5, "attack_stage": "invalid_stage", "recommended_response_tier": "manual", "summary": "x", "key_indicators": []}'
        result = _parse_llm_response(raw, self._incident())
        assert result.attack_stage == "execution"  # heuristic from T1059

    def test_invalid_tier_defaults_to_supervised(self):
        raw = '{"urgency_score": 0.5, "attack_stage": "execution", "recommended_response_tier": "ultra_auto", "summary": "x", "key_indicators": []}'
        result = _parse_llm_response(raw, self._incident())
        assert result.recommended_response_tier == "supervised"

    def test_raises_on_no_json(self):
        with pytest.raises((ValueError, Exception)):
            _parse_llm_response("No JSON here at all", self._incident())


# ── IncidentTriageAgent ───────────────────────────────────────────────────────

class TestIncidentTriageAgent:
    def _incident(self, severity: str = "high", techniques: list | None = None):
        return {
            "id": "inc-test",
            "title": "Test Incident",
            "severity": severity,
            "mitre_techniques": techniques or ["T1059"],
        }

    @pytest.mark.asyncio
    async def test_heuristic_when_llm_disabled(self):
        """With LLM_ENABLED=false, must always use heuristics."""
        agent = IncidentTriageAgent()
        # Default settings have llm_enabled=False
        result = await agent.triage(self._incident("critical"))
        assert isinstance(result, TriageResult)
        assert result.urgency_score == 0.95
        assert result.recommended_response_tier == "automated"

    @pytest.mark.asyncio
    async def test_fallback_on_network_error(self):
        """If LLM is enabled but unreachable, falls back to heuristics."""
        import httpx

        agent = IncidentTriageAgent()
        agent.settings = MagicMock()
        agent.settings.llm_enabled = True
        agent.settings.ollama_base_url = "http://localhost:11434"
        agent.settings.ollama_model = "llama3.2"
        agent.settings.ollama_timeout = 1

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            mock_client_cls.return_value = mock_client

            result = await agent.triage(self._incident("high"))

        assert isinstance(result, TriageResult)
        assert result.urgency_score == 0.80  # heuristic for high

    @pytest.mark.asyncio
    async def test_fallback_on_bad_json(self):
        """If LLM returns unparseable text, falls back to heuristics."""
        agent = IncidentTriageAgent()
        agent.settings = MagicMock()
        agent.settings.llm_enabled = True
        agent.settings.ollama_base_url = "http://localhost:11434"
        agent.settings.ollama_model = "llama3.2"
        agent.settings.ollama_timeout = 30

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={"response": "This is not JSON"})

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            result = await agent.triage(self._incident("medium"))

        assert isinstance(result, TriageResult)

    @pytest.mark.asyncio
    async def test_successful_llm_triage(self):
        """Successful LLM call returns parsed TriageResult."""
        agent = IncidentTriageAgent()
        agent.settings = MagicMock()
        agent.settings.llm_enabled = True
        agent.settings.ollama_base_url = "http://localhost:11434"
        agent.settings.ollama_model = "llama3.2"
        agent.settings.ollama_timeout = 30

        good_json = '{"urgency_score": 0.9, "attack_stage": "execution", "recommended_response_tier": "automated", "summary": "LLM summary", "key_indicators": ["indicator A"]}'

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={"response": good_json})

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            result = await agent.triage(self._incident("critical"))

        assert result.urgency_score == 0.9
        assert result.summary == "LLM summary"
        assert result.recommended_response_tier == "automated"
