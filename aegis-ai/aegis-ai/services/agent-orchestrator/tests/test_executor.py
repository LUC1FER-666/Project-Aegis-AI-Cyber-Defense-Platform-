"""Unit tests for ActionExecutor — no live Elasticsearch or asset-discovery service."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.agents.executor import ActionExecutor
from app.agents.playbooks import ActionStep


INCIDENT = {
    "id": "inc-001",
    "title": "Brute Force Attack",
    "severity": "high",
    "mitre_techniques": ["T1110"],
    "asset_ids": ["asset-xyz"],
    "evidence": {"src_ip": "10.0.0.99", "users": ["admin", "root"]},
    "affected_users": ["admin", "root"],
}


def _make_step(action_type: str, target: str = "asset-xyz") -> ActionStep:
    return ActionStep(
        action_type=action_type,
        target=target,
        parameters={
            "incident_id": "inc-001",
            "asset_ids": ["asset-xyz"],
            "severity": "high",
        },
    )


class TestActionExecutor:
    def setup_method(self):
        self.executor = ActionExecutor()

    # ── Result schema validation ──────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_result_has_required_fields(self):
        step = _make_step("block_ip")
        result = await self.executor.execute(step, INCIDENT)
        for key in ("action_id", "action_type", "target", "status", "result_data", "duration_ms", "executed_at"):
            assert key in result, f"Missing key: {key}"

    @pytest.mark.asyncio
    async def test_action_id_is_uuid_string(self):
        import re
        step = _make_step("notify_soc")
        result = await self.executor.execute(step, INCIDENT)
        uuid_pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        )
        assert uuid_pattern.match(result["action_id"])

    @pytest.mark.asyncio
    async def test_duration_ms_is_non_negative_int(self):
        step = _make_step("collect_logs")
        result = await self.executor.execute(step, INCIDENT)
        assert isinstance(result["duration_ms"], int)
        assert result["duration_ms"] >= 0

    # ── block_ip ─────────────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_block_ip_extracts_src_ip(self):
        step = _make_step("block_ip")
        result = await self.executor.execute(step, INCIDENT)
        assert result["status"] == "success"
        assert result["result_data"]["blocked_ip"] == "10.0.0.99"
        assert "rule_id" in result["result_data"]

    @pytest.mark.asyncio
    async def test_block_ip_fallback_when_no_src_ip(self):
        step = _make_step("block_ip")
        incident_no_ip = {**INCIDENT, "evidence": {}}
        result = await self.executor.execute(step, incident_no_ip)
        assert result["status"] == "success"
        assert result["result_data"]["blocked_ip"] == "0.0.0.0"

    # ── isolate_host ─────────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_isolate_host_returns_asset_id(self):
        step = _make_step("isolate_host")
        result = await self.executor.execute(step, INCIDENT)
        assert result["status"] == "success"
        assert result["result_data"]["asset_id"] == "asset-xyz"
        assert "isolation_time" in result["result_data"]

    # ── kill_process ──────────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_kill_process_extracts_process_name(self):
        incident = {
            **INCIDENT,
            "evidence": {"process_name": "malware.exe", "pid": 1234},
        }
        step = _make_step("kill_process")
        result = await self.executor.execute(step, incident)
        assert result["status"] == "success"
        assert result["result_data"]["process_name"] == "malware.exe"
        assert result["result_data"]["pid"] == 1234
        assert result["result_data"]["signal"] == "SIGKILL"

    @pytest.mark.asyncio
    async def test_kill_process_fallback_process_name(self):
        step = _make_step("kill_process")
        incident_no_proc = {**INCIDENT, "evidence": {}}
        result = await self.executor.execute(step, incident_no_proc)
        assert result["status"] == "success"
        assert result["result_data"]["process_name"] == "suspicious.exe"

    # ── collect_logs ──────────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_collect_logs_returns_expected_fields(self):
        step = _make_step("collect_logs")
        result = await self.executor.execute(step, INCIDENT)
        assert result["status"] == "success"
        data = result["result_data"]
        assert "log_count" in data
        assert "time_range" in data
        assert "sample" in data
        assert isinstance(data["log_count"], int)

    # ── notify_soc ────────────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_notify_soc_returns_notification_id(self):
        step = _make_step("notify_soc")
        result = await self.executor.execute(step, INCIDENT)
        assert result["status"] == "success"
        assert "notification_id" in result["result_data"]
        assert "recipients" in result["result_data"]
        assert len(result["result_data"]["recipients"]) > 0

    @pytest.mark.asyncio
    async def test_notify_soc_critical_includes_ciso(self):
        step = _make_step("notify_soc")
        critical_incident = {**INCIDENT, "severity": "critical"}
        result = await self.executor.execute(step, critical_incident)
        recipients = result["result_data"]["recipients"]
        assert any("ciso" in r for r in recipients)

    # ── force_password_reset ──────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_force_password_reset_uses_affected_users(self):
        step = _make_step("force_password_reset")
        result = await self.executor.execute(step, INCIDENT)
        assert result["status"] == "success"
        data = result["result_data"]
        assert "user_list" in data
        assert "reset_token_count" in data
        assert data["reset_token_count"] == len(data["user_list"])

    @pytest.mark.asyncio
    async def test_force_password_reset_fallback_users(self):
        step = _make_step("force_password_reset")
        incident_no_users = {**INCIDENT, "affected_users": None, "evidence": {}}
        result = await self.executor.execute(step, incident_no_users)
        assert result["status"] == "success"
        assert len(result["result_data"]["user_list"]) > 0

    # ── escalate_to_analyst ───────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_escalate_creates_ticket(self):
        step = _make_step("escalate_to_analyst")
        result = await self.executor.execute(step, INCIDENT)
        assert result["status"] == "success"
        data = result["result_data"]
        assert "ticket_id" in data
        assert "assigned_to" in data
        assert "priority" in data

    @pytest.mark.asyncio
    async def test_escalate_critical_is_p1(self):
        step = _make_step("escalate_to_analyst")
        critical = {**INCIDENT, "severity": "critical"}
        result = await self.executor.execute(step, critical)
        assert result["result_data"]["priority"] == "P1"

    @pytest.mark.asyncio
    async def test_escalate_low_is_p4(self):
        step = _make_step("escalate_to_analyst")
        low = {**INCIDENT, "severity": "low"}
        result = await self.executor.execute(step, low)
        assert result["result_data"]["priority"] == "P4"

    # ── enrich_asset ─────────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_enrich_asset_handles_http_success(self):
        step = _make_step("enrich_asset")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json = MagicMock(return_value={"id": "asset-xyz", "hostname": "web01"})

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_cls.return_value = mock_client

            result = await self.executor.execute(step, INCIDENT)

        assert result["status"] == "success"
        data = result["result_data"]
        assert data["enriched"] is True

    @pytest.mark.asyncio
    async def test_enrich_asset_handles_network_error(self):
        """Network failure must not crash — returns enriched=False."""
        import httpx

        step = _make_step("enrich_asset")

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
            mock_cls.return_value = mock_client

            result = await self.executor.execute(step, INCIDENT)

        assert result["status"] == "success"  # outer execute catches errors too
        assert result["result_data"]["enriched"] is False

    @pytest.mark.asyncio
    async def test_enrich_asset_no_asset_ids(self):
        step = _make_step("enrich_asset")
        incident_no_assets = {**INCIDENT, "asset_ids": []}
        result = await self.executor.execute(step, incident_no_assets)
        assert result["status"] == "success"
        assert result["result_data"]["enriched"] is False

    # ── Unknown action type ───────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_unknown_action_returns_skipped(self):
        step = ActionStep("nonexistent_action", "target")
        result = await self.executor.execute(step, INCIDENT)
        assert result["status"] == "skipped"
        assert "error" in result["result_data"]
