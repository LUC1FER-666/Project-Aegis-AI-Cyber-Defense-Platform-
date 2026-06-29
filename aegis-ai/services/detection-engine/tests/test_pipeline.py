"""
Tests — Detection Pipeline Integration

Tests the full pipeline with mocked DB, mocked LLM, real Sigma + ML engines.
Covers:
- Sigma hit → alert created
- ML anomaly → alert created
- LLM suppression respected
- Evidence extraction
- Timestamp parsing
"""
import uuid
import pytest
import pytest_asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch, ANY

from app.engines.sigma_engine import SigmaRuleEngine
from app.engines.ml_engine import MLAnomalyDetector
from app.engines.llm_engine import LLMReasoningEngine, LLMValidationResult
from app.engines.correlator import AlertCorrelator
from app.pipeline import DetectionPipeline


@pytest.fixture
def sigma_engine():
    engine = SigmaRuleEngine(rules_path="/nonexistent")
    engine.load_rule_dict({
        "title": "PowerShell Encoded",
        "id": "test-ps-enc",
        "level": "high",
        "tags": ["attack.t1059.001", "attack.execution"],
        "logsource": {},
        "detection": {
            "selection": {"CommandLine|contains": "-EncodedCommand"},
            "condition": "selection",
        },
    })
    return engine


@pytest.fixture
def ml_engine():
    return MLAnomalyDetector(min_samples=999999, contamination=0.05)  # won't train in tests


@pytest.fixture
def llm_engine_pass():
    """LLM that always approves alerts."""
    engine = LLMReasoningEngine(enabled=False)
    return engine


@pytest.fixture
def llm_engine_suppress():
    """LLM that always suppresses."""
    engine = LLMReasoningEngine(enabled=True, ollama_base_url="http://mock")
    engine.validate_alert = AsyncMock(return_value=LLMValidationResult(
        is_true_positive=False,
        confidence=0.95,
        reasoning="This is a false positive.",
        suppressed=True,
    ))
    return engine


@pytest.fixture
def correlator():
    return AlertCorrelator(window_seconds=300, min_alerts=2)


def _make_pipeline(sigma, ml, llm, correlator):
    return DetectionPipeline(
        sigma_engine=sigma,
        ml_detector=ml,
        llm_engine=llm,
        correlator=correlator,
        kafka_publisher=None,
    )


def _make_db_session():
    """Create a minimal async mock for SQLAlchemy AsyncSession."""
    db = AsyncMock()

    # execute() returns a mock with scalar_one_or_none() → None (no existing rule)
    execute_result = MagicMock()
    execute_result.scalar_one_or_none = MagicMock(return_value=None)
    db.execute = AsyncMock(return_value=execute_result)
    db.add = MagicMock()
    db.flush = AsyncMock()

    return db


class TestDetectionPipelineCounters:
    @pytest.mark.asyncio
    async def test_events_processed_increments(self, sigma_engine, ml_engine, llm_engine_pass, correlator):
        pipeline = _make_pipeline(sigma_engine, ml_engine, llm_engine_pass, correlator)
        db = _make_db_session()

        event = {"CommandLine": "notepad.exe", "log_type": "process"}
        await pipeline.process_event(event, db)
        assert pipeline.events_processed == 1

    @pytest.mark.asyncio
    async def test_sigma_hit_increments_counter(self, sigma_engine, ml_engine, llm_engine_pass, correlator):
        pipeline = _make_pipeline(sigma_engine, ml_engine, llm_engine_pass, correlator)
        db = _make_db_session()

        event = {"CommandLine": "powershell -EncodedCommand abc", "log_type": "process"}
        await pipeline.process_event(event, db)
        assert pipeline.sigma_hits == 1

    @pytest.mark.asyncio
    async def test_no_hit_on_benign_event(self, sigma_engine, ml_engine, llm_engine_pass, correlator):
        pipeline = _make_pipeline(sigma_engine, ml_engine, llm_engine_pass, correlator)
        db = _make_db_session()

        event = {"CommandLine": "notepad.exe document.txt", "log_type": "process"}
        await pipeline.process_event(event, db)
        assert pipeline.sigma_hits == 0
        assert pipeline.alerts_created == 0

    @pytest.mark.asyncio
    async def test_llm_suppression_increments_suppressed_counter(
        self, sigma_engine, ml_engine, llm_engine_suppress, correlator
    ):
        pipeline = _make_pipeline(sigma_engine, ml_engine, llm_engine_suppress, correlator)
        db = _make_db_session()

        event = {"CommandLine": "powershell -EncodedCommand abc", "log_type": "process"}
        alerts = await pipeline.process_event(event, db)
        assert alerts == []  # suppressed → no alerts returned
        assert pipeline.alerts_suppressed == 1
        assert pipeline.alerts_created == 0

    @pytest.mark.asyncio
    async def test_sigma_hit_creates_alert_in_db(self, sigma_engine, ml_engine, llm_engine_pass, correlator):
        pipeline = _make_pipeline(sigma_engine, ml_engine, llm_engine_pass, correlator)
        db = _make_db_session()

        event = {"CommandLine": "powershell -EncodedCommand abc", "log_type": "process"}
        alerts = await pipeline.process_event(event, db)

        # db.add should have been called with an Alert object
        assert db.add.called
        assert len(alerts) == 1

    @pytest.mark.asyncio
    async def test_alert_dict_has_required_fields(self, sigma_engine, ml_engine, llm_engine_pass, correlator):
        pipeline = _make_pipeline(sigma_engine, ml_engine, llm_engine_pass, correlator)
        db = _make_db_session()

        event = {
            "CommandLine": "powershell -EncodedCommand abc",
            "log_type": "process",
            "hostname": "test-host",
        }
        alerts = await pipeline.process_event(event, db)
        assert len(alerts) == 1
        alert = alerts[0]
        assert "alert_id" in alert
        assert "rule_id" in alert
        assert "severity" in alert
        assert "mitre_technique" in alert
        assert "confidence_score" in alert
        assert "evidence" in alert
        assert "timestamp" in alert

    @pytest.mark.asyncio
    async def test_alert_mitre_technique_from_rule(self, sigma_engine, ml_engine, llm_engine_pass, correlator):
        pipeline = _make_pipeline(sigma_engine, ml_engine, llm_engine_pass, correlator)
        db = _make_db_session()

        event = {"CommandLine": "powershell -EncodedCommand abc", "log_type": "process"}
        alerts = await pipeline.process_event(event, db)
        assert alerts[0]["mitre_technique"] == "T1059.001"


class TestEvidenceExtraction:
    def test_extracts_known_fields(self):
        pipeline = DetectionPipeline.__new__(DetectionPipeline)
        evidence = pipeline._extract_evidence({
            "hostname": "web-01",
            "CommandLine": "cmd.exe /c whoami",
            "user": "SYSTEM",
            "src_ip": "10.0.1.5",
            "dst_ip": "1.2.3.4",
            "dst_port": 4444,
            "log_type": "process",
            "ignored_field": "should_not_appear",
        })
        assert evidence["hostname"] == "web-01"
        assert evidence["CommandLine"] == "cmd.exe /c whoami"
        assert evidence["user"] == "SYSTEM"
        assert evidence["dst_port"] == 4444
        assert "ignored_field" not in evidence

    def test_truncates_long_strings(self):
        pipeline = DetectionPipeline.__new__(DetectionPipeline)
        long_cmd = "x" * 1000
        evidence = pipeline._extract_evidence({"CommandLine": long_cmd})
        assert len(evidence["CommandLine"]) <= 530  # 512 + marker

    def test_empty_event_returns_empty_evidence(self):
        pipeline = DetectionPipeline.__new__(DetectionPipeline)
        evidence = pipeline._extract_evidence({})
        assert evidence == {}

    def test_none_values_excluded(self):
        pipeline = DetectionPipeline.__new__(DetectionPipeline)
        evidence = pipeline._extract_evidence({"hostname": None, "user": "admin"})
        assert "hostname" not in evidence
        assert evidence["user"] == "admin"


class TestTimestampParsing:
    def test_iso_string(self):
        result = DetectionPipeline._parse_ts("2024-06-15T14:30:00Z")
        assert result is not None
        assert result.hour == 14

    def test_iso_string_with_offset(self):
        result = DetectionPipeline._parse_ts("2024-06-15T14:30:00+05:30")
        assert result is not None

    def test_epoch_integer(self):
        result = DetectionPipeline._parse_ts(1718463000)
        assert result is not None

    def test_epoch_float(self):
        result = DetectionPipeline._parse_ts(1718463000.5)
        assert result is not None

    def test_none_returns_none(self):
        assert DetectionPipeline._parse_ts(None) is None

    def test_invalid_string_returns_none(self):
        assert DetectionPipeline._parse_ts("not-a-timestamp") is None


class TestMLAlertCreation:
    @pytest.mark.asyncio
    async def test_ml_anomaly_creates_alert(self, sigma_engine, correlator, llm_engine_pass):
        """Manually patch ML engine to report an anomaly."""
        ml = MLAnomalyDetector(min_samples=10, contamination=0.1)
        pipeline = _make_pipeline(sigma_engine, ml, llm_engine_pass, correlator)

        # Monkey-patch score_event to return high anomaly
        ml.score_event = MagicMock(return_value=(0.92, True))

        db = _make_db_session()
        event = {
            "log_type": "process",
            "command_line": "unusual_process.exe",
        }
        alerts = await pipeline.process_event(event, db)
        # ML alert should have been created
        assert pipeline.ml_anomalies == 1
        ml_alerts = [a for a in alerts if a["rule_id"] == "aegis-ml-isolation-forest"]
        assert len(ml_alerts) == 1
        assert ml_alerts[0]["confidence_score"] == 0.92

    @pytest.mark.asyncio
    async def test_ml_low_score_no_alert(self, sigma_engine, correlator, llm_engine_pass):
        ml = MLAnomalyDetector(min_samples=10, contamination=0.1)
        ml.score_event = MagicMock(return_value=(0.4, False))
        pipeline = _make_pipeline(sigma_engine, ml, llm_engine_pass, correlator)
        db = _make_db_session()
        await pipeline.process_event({"log_type": "process", "command_line": "normal.exe"}, db)
        assert pipeline.ml_anomalies == 0
