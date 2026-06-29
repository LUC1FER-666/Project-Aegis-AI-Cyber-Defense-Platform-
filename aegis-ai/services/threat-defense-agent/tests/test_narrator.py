"""Unit tests for AttackNarrativeEngine."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.agents.narrator import (
    AttackNarrativeEngine,
    _heuristic_narrative,
    _parse_llm_narrative,
)


CONTEXT = {
    "title": "Brute Force Attack",
    "severity": "high",
    "mitre_techniques": ["T1110"],
    "affected_assets": ["dc-01"],
    "confidence": 0.85,
    "evidence_summary": "15 auth failures from 10.0.0.1",
}


class TestHeuristicNarrative:
    def test_returns_all_required_fields(self):
        result = _heuristic_narrative(CONTEXT)
        for field in ("headline", "severity_assessment", "attack_timeline",
                      "likely_objective", "immediate_actions", "technical_indicators", "confidence"):
            assert field in result, f"Missing: {field}"

    def test_headline_contains_title(self):
        result = _heuristic_narrative(CONTEXT)
        assert "Brute Force" in result["headline"]

    def test_timeline_is_list(self):
        result = _heuristic_narrative(CONTEXT)
        assert isinstance(result["attack_timeline"], list)
        assert len(result["attack_timeline"]) >= 2

    def test_immediate_actions_non_empty(self):
        result = _heuristic_narrative(CONTEXT)
        assert len(result["immediate_actions"]) > 0

    def test_confidence_preserved(self):
        result = _heuristic_narrative(CONTEXT)
        assert result["confidence"] == 0.85

    def test_empty_context_does_not_crash(self):
        result = _heuristic_narrative({})
        assert isinstance(result, dict)
        assert "headline" in result

    def test_critical_severity_in_assessment(self):
        ctx = {**CONTEXT, "severity": "critical"}
        result = _heuristic_narrative(ctx)
        assert "Critical" in result["severity_assessment"] or "critical" in result["severity_assessment"].lower()

    def test_assets_appear_in_indicators(self):
        result = _heuristic_narrative(CONTEXT)
        indicators_text = " ".join(result["technical_indicators"])
        assert "dc-01" in indicators_text

    def test_techniques_in_timeline_when_present(self):
        result = _heuristic_narrative(CONTEXT)
        timeline_text = " ".join(result["attack_timeline"])
        assert "T1110" in timeline_text


class TestParseLlmNarrative:
    def _ctx(self):
        return {"confidence": 0.8, "mitre_techniques": ["T1059"]}

    def test_parses_valid_json(self):
        raw = """{
            "headline": "PowerShell attack detected",
            "severity_assessment": "High — urgent response needed",
            "attack_timeline": ["Step 1", "Step 2"],
            "likely_objective": "Credential theft",
            "immediate_actions": ["Isolate host", "Collect logs"],
            "technical_indicators": ["powershell.exe", "encoded command"],
            "confidence": 0.9
        }"""
        result = _parse_llm_narrative(raw, self._ctx())
        assert result["headline"] == "PowerShell attack detected"
        assert result["confidence"] == 0.9
        assert len(result["attack_timeline"]) == 2

    def test_strips_markdown_fences(self):
        raw = "```json\n{\"headline\": \"Test\", \"severity_assessment\": \"High\", \"attack_timeline\": [], \"likely_objective\": \"x\", \"immediate_actions\": [], \"technical_indicators\": [], \"confidence\": 0.5}\n```"
        result = _parse_llm_narrative(raw, self._ctx())
        assert result["headline"] == "Test"

    def test_clamps_confidence(self):
        raw = '{"headline":"x","severity_assessment":"y","attack_timeline":[],"likely_objective":"z","immediate_actions":[],"technical_indicators":[],"confidence":1.5}'
        result = _parse_llm_narrative(raw, self._ctx())
        assert result["confidence"] == 1.0

    def test_raises_on_no_json(self):
        with pytest.raises(Exception):
            _parse_llm_narrative("No JSON here", self._ctx())

    def test_handles_non_list_timeline(self):
        raw = '{"headline":"x","severity_assessment":"y","attack_timeline":"single step","likely_objective":"z","immediate_actions":[],"technical_indicators":[],"confidence":0.5}'
        result = _parse_llm_narrative(raw, self._ctx())
        assert isinstance(result["attack_timeline"], list)


class TestAttackNarrativeEngine:
    @pytest.mark.asyncio
    async def test_heuristic_when_llm_disabled(self):
        engine = AttackNarrativeEngine()
        # Default settings: llm_enabled=False
        result = await engine.generate(CONTEXT)
        assert isinstance(result, dict)
        assert "headline" in result

    @pytest.mark.asyncio
    async def test_fallback_on_network_error(self):
        import httpx
        engine = AttackNarrativeEngine()
        engine.settings = MagicMock()
        engine.settings.llm_enabled = True
        engine.settings.ollama_base_url = "http://localhost:11434"
        engine.settings.ollama_model = "llama3.2"
        engine.settings.ollama_timeout = 1

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))
            mock_cls.return_value = mock_client

            result = await engine.generate(CONTEXT)

        assert isinstance(result, dict)
        assert "headline" in result

    @pytest.mark.asyncio
    async def test_successful_llm_call(self):
        engine = AttackNarrativeEngine()
        engine.settings = MagicMock()
        engine.settings.llm_enabled = True
        engine.settings.ollama_base_url = "http://localhost:11434"
        engine.settings.ollama_model = "llama3.2"
        engine.settings.ollama_timeout = 30

        good_json = '{"headline":"Attack detected","severity_assessment":"High","attack_timeline":["Step 1"],"likely_objective":"Data theft","immediate_actions":["Isolate"],"technical_indicators":["IOC1"],"confidence":0.9}'

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={"response": good_json})

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_cls.return_value = mock_client

            result = await engine.generate(CONTEXT)

        assert result["headline"] == "Attack detected"
        assert result["confidence"] == 0.9
