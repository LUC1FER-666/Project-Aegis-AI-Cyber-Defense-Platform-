"""Unit tests for PreemptiveActionEngine — mocks Kafka publish."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch

from app.agents.preemptive import PreemptiveActionEngine, THREAT_ACTION_MAP


PREDICTION = {
    "prediction_id": "pred-abc123",
    "threat_type": "brute_force_imminent",
    "confidence": 0.85,
    "affected_assets": ["host-01", "host-02"],
    "evidence_summary": "5 auth failures from 10.0.0.1 in last 5 minutes",
    "recommended_actions": ["rate_limit_ip", "alert_soc"],
}


@pytest.fixture(autouse=True)
def mock_kafka():
    with patch("app.agents.preemptive.kafka.publish", new_callable=AsyncMock) as m:
        m.return_value = True
        yield m


class TestPreemptiveActionEngine:
    def setup_method(self):
        self.engine = PreemptiveActionEngine()

    @pytest.mark.asyncio
    async def test_brute_force_executes_rate_limit_and_alert(self):
        results = await self.engine.execute_for_prediction(PREDICTION)
        types = [r["action_type"] for r in results]
        assert "rate_limit_ip" in types
        assert "alert_soc" in types

    @pytest.mark.asyncio
    async def test_all_results_have_required_fields(self):
        results = await self.engine.execute_for_prediction(PREDICTION)
        for r in results:
            for field in ("action_id", "action_type", "target", "status",
                         "result_data", "confidence_trigger", "prediction_id",
                         "executed_at", "duration_ms", "rationale"):
                assert field in r, f"Missing field: {field}"

    @pytest.mark.asyncio
    async def test_confidence_trigger_matches_prediction(self):
        results = await self.engine.execute_for_prediction(PREDICTION)
        for r in results:
            assert r["confidence_trigger"] == 0.85

    @pytest.mark.asyncio
    async def test_dns_tunnel_actions(self):
        pred = {**PREDICTION, "threat_type": "dns_tunnel_imminent", "confidence": 0.80}
        results = await self.engine.execute_for_prediction(pred)
        types = [r["action_type"] for r in results]
        assert "enable_dns_inspection" in types
        assert "alert_soc" in types

    @pytest.mark.asyncio
    async def test_c2_beacon_actions(self):
        pred = {**PREDICTION, "threat_type": "c2_beacon_imminent", "confidence": 0.75}
        results = await self.engine.execute_for_prediction(pred)
        types = [r["action_type"] for r in results]
        assert "isolate_asset_preemptively" in types

    @pytest.mark.asyncio
    async def test_account_compromise_actions(self):
        pred = {**PREDICTION, "threat_type": "account_compromise", "confidence": 0.90}
        results = await self.engine.execute_for_prediction(pred)
        types = [r["action_type"] for r in results]
        assert "force_mfa_challenge" in types
        assert "lock_account_temporarily" in types
        assert "alert_soc" in types

    @pytest.mark.asyncio
    async def test_lateral_spread_actions(self):
        pred = {**PREDICTION, "threat_type": "lateral_spread_imminent", "confidence": 0.88}
        results = await self.engine.execute_for_prediction(pred)
        types = [r["action_type"] for r in results]
        assert "segment_network" in types

    @pytest.mark.asyncio
    async def test_status_is_executed_on_success(self):
        results = await self.engine.execute_for_prediction(PREDICTION)
        for r in results:
            assert r["status"] in ("executed", "skipped")

    @pytest.mark.asyncio
    async def test_unknown_threat_type_falls_back_to_alert_soc(self):
        pred = {**PREDICTION, "threat_type": "unknown_threat_xyz"}
        results = await self.engine.execute_for_prediction(pred)
        types = [r["action_type"] for r in results]
        assert "alert_soc" in types

    @pytest.mark.asyncio
    async def test_rate_limit_extracts_ip_from_evidence(self):
        results = await self.engine.execute_for_prediction(PREDICTION)
        rl = next(r for r in results if r["action_type"] == "rate_limit_ip")
        assert rl["result_data"].get("blocked_ip") == "10.0.0.1" or rl["result_data"].get("target_ip") == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_never_raises_on_bad_prediction(self):
        """Engine must not crash even with empty/malformed prediction."""
        results = await self.engine.execute_for_prediction({})
        assert isinstance(results, list)

    def test_all_threat_types_have_action_map(self):
        threat_types = [
            "brute_force_imminent", "dns_tunnel_imminent",
            "c2_beacon_imminent", "account_compromise", "lateral_spread_imminent",
        ]
        for t in threat_types:
            assert t in THREAT_ACTION_MAP, f"Missing action map for: {t}"
