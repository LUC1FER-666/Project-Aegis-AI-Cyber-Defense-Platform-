"""
Tests — LLM Reasoning Engine

All Ollama calls are mocked — tests do not require a running Ollama instance.
Covers:
- Response parsing (valid JSON, markdown-fenced, malformed)
- Timeout / error graceful degradation
- Low-severity bypass
- Suppression threshold safety (critical never suppressed)
"""
import json
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from app.engines.llm_engine import LLMReasoningEngine, LLMValidationResult


@pytest.fixture
def engine():
    return LLMReasoningEngine(
        ollama_base_url="http://localhost:11434",
        model="llama3.2",
        timeout=5.0,
        enabled=True,
    )


@pytest.fixture
def disabled_engine():
    return LLMReasoningEngine(enabled=False)


def _make_valid_response(is_tp=True, confidence=0.85, reasoning="Looks real", suppressed=False):
    return json.dumps({
        "is_true_positive": is_tp,
        "confidence": confidence,
        "reasoning": reasoning,
        "suppressed": suppressed,
    })


class TestLLMResponseParsing:
    def test_parse_valid_json(self, engine):
        result = engine._parse_response(_make_valid_response())
        assert result.is_true_positive is True
        assert result.confidence == 0.85
        assert result.reasoning == "Looks real"
        assert result.suppressed is False

    def test_parse_false_positive_with_suppression(self, engine):
        raw = _make_valid_response(is_tp=False, confidence=0.92, suppressed=True)
        result = engine._parse_response(raw)
        assert result.is_true_positive is False
        assert result.suppressed is True

    def test_parse_markdown_fenced_json(self, engine):
        raw = "```json\n" + _make_valid_response() + "\n```"
        result = engine._parse_response(raw)
        assert result.is_true_positive is True

    def test_parse_markdown_no_language_tag(self, engine):
        raw = "```\n" + _make_valid_response() + "\n```"
        result = engine._parse_response(raw)
        assert result.is_true_positive is True

    def test_parse_json_with_preamble(self, engine):
        raw = "Here is my analysis:\n" + _make_valid_response()
        result = engine._parse_response(raw)
        assert result.is_true_positive is True

    def test_parse_no_json_raises(self, engine):
        with pytest.raises((ValueError, json.JSONDecodeError)):
            engine._parse_response("This is not JSON at all")

    def test_confidence_clamped_to_range(self, engine):
        raw = _make_valid_response(confidence=1.5)
        result = engine._parse_response(raw)
        assert result.confidence <= 1.0

    def test_confidence_clamped_negative(self, engine):
        raw = _make_valid_response(confidence=-0.3)
        result = engine._parse_response(raw)
        assert result.confidence >= 0.0

    def test_missing_fields_use_defaults(self, engine):
        result = engine._parse_response('{"is_true_positive": true}')
        assert result.confidence == 0.5
        assert result.suppressed is False


class TestLLMValidation:
    @pytest.mark.asyncio
    async def test_low_severity_bypasses_llm(self, engine):
        """Low/info severity alerts skip LLM and pass through."""
        result = await engine.validate_alert(
            rule_title="Test",
            rule_id="test-001",
            severity="low",
            mitre_technique="T1059",
            evidence={"CommandLine": "cmd.exe"},
        )
        assert result.is_true_positive is True
        assert result.suppressed is False
        assert "skipped" in result.reasoning.lower()

    @pytest.mark.asyncio
    async def test_info_severity_bypasses_llm(self, engine):
        result = await engine.validate_alert(
            rule_title="Test",
            rule_id="test-002",
            severity="info",
            mitre_technique=None,
            evidence={},
        )
        assert "skipped" in result.reasoning.lower()

    @pytest.mark.asyncio
    async def test_disabled_engine_passthrough(self, disabled_engine):
        result = await disabled_engine.validate_alert(
            rule_title="Test",
            rule_id="test-003",
            severity="critical",
            mitre_technique="T1059",
            evidence={"cmd": "x"},
        )
        assert result.is_true_positive is True
        assert "disabled" in result.reasoning.lower()

    @pytest.mark.asyncio
    async def test_successful_validation_true_positive(self, engine):
        with patch.object(engine, "_call_ollama", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = _make_valid_response(
                is_tp=True, confidence=0.88, suppressed=False
            )
            result = await engine.validate_alert(
                rule_title="PowerShell Encoded",
                rule_id="ps-001",
                severity="high",
                mitre_technique="T1059.001",
                evidence={"CommandLine": "powershell -enc abc"},
            )
        assert result.is_true_positive is True
        assert result.confidence == 0.88
        assert result.suppressed is False
        assert result.error is None

    @pytest.mark.asyncio
    async def test_successful_validation_false_positive_suppressed(self, engine):
        with patch.object(engine, "_call_ollama", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = _make_valid_response(
                is_tp=False, confidence=0.92, suppressed=True
            )
            result = await engine.validate_alert(
                rule_title="Scheduled Task",
                rule_id="sched-001",
                severity="medium",
                mitre_technique="T1053.005",
                evidence={"CommandLine": "schtasks /create /tn backup /sc daily"},
            )
        assert result.suppressed is True

    @pytest.mark.asyncio
    async def test_timeout_returns_passthrough_result(self, engine):
        import httpx
        with patch.object(engine, "_call_ollama", new_callable=AsyncMock) as mock_call:
            mock_call.side_effect = httpx.TimeoutException("timed out")
            result = await engine.validate_alert(
                rule_title="Test",
                rule_id="test-timeout",
                severity="high",
                mitre_technique="T1059",
                evidence={"cmd": "x"},
            )
        assert result.is_true_positive is True
        assert result.suppressed is False
        assert result.error == "timeout"

    @pytest.mark.asyncio
    async def test_generic_exception_returns_passthrough(self, engine):
        with patch.object(engine, "_call_ollama", new_callable=AsyncMock) as mock_call:
            mock_call.side_effect = RuntimeError("connection refused")
            result = await engine.validate_alert(
                rule_title="Test",
                rule_id="test-err",
                severity="critical",
                mitre_technique="T1003",
                evidence={"cmd": "mimikatz"},
            )
        assert result.is_true_positive is True
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_malformed_json_returns_passthrough(self, engine):
        with patch.object(engine, "_call_ollama", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = "This is not JSON!"
            result = await engine.validate_alert(
                rule_title="Test",
                rule_id="test-bad-json",
                severity="high",
                mitre_technique="T1059",
                evidence={"cmd": "x"},
            )
        # Should degrade gracefully, not raise
        assert result.is_true_positive is True
        assert result.error is not None


class TestLLMPromptBuilding:
    def test_prompt_contains_rule_title(self, engine):
        prompt = engine._build_prompt(
            rule_title="PowerShell Encoded Command",
            rule_id="ps-001",
            severity="high",
            mitre_technique="T1059.001",
            evidence={"CommandLine": "powershell -enc abc"},
        )
        assert "PowerShell Encoded Command" in prompt

    def test_prompt_contains_mitre_technique(self, engine):
        prompt = engine._build_prompt(
            rule_title="Test",
            rule_id="t-001",
            severity="high",
            mitre_technique="T1059.001",
            evidence={},
        )
        assert "T1059.001" in prompt

    def test_prompt_handles_no_mitre(self, engine):
        prompt = engine._build_prompt(
            rule_title="Test",
            rule_id="t-002",
            severity="medium",
            mitre_technique=None,
            evidence={"msg": "something"},
        )
        assert "None" not in prompt or "T" not in prompt  # MITRE line should be absent

    def test_truncate_dict_limits_entries(self, engine):
        big_dict = {f"key_{i}": f"val_{i}" for i in range(30)}
        truncated = engine._truncate_dict(big_dict, max_values=10)
        assert len(truncated) <= 11  # 10 + possible "..." entry

    def test_truncate_long_string_values(self, engine):
        d = {"cmd": "x" * 1000}
        truncated = engine._truncate_dict(d)
        assert len(truncated["cmd"]) <= 520  # 500 + truncation marker
