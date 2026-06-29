"""Unit tests for SOCNotificationSystem and SSE helpers."""
from __future__ import annotations

import asyncio

import pytest

from app.agents.notifier import (
    SOCNotificationSystem,
    broadcast,
    register_subscriber,
    unregister_subscriber,
    _confidence_to_severity,
)

PREDICTION = {
    "prediction_id": "pred-001",
    "threat_type": "brute_force_imminent",
    "confidence": 0.85,
    "affected_assets": ["host-01"],
    "evidence_summary": "5 failures from 10.0.0.1",
    "recommended_actions": ["rate_limit_ip"],
}

INCIDENT = {
    "incident_id": "inc-001",
    "title": "Brute Force Attack",
    "severity": "high",
    "affected_assets": ["dc-01"],
    "alert_count": 5,
}

ACTION = {
    "action_id": "act-001",
    "action_type": "rate_limit_ip",
    "target": "host-01",
    "status": "executed",
    "confidence_trigger": 0.85,
    "result_data": {"rule_id": "RL-ABC"},
}


class TestConfidenceToSeverity:
    def test_090_is_critical(self):
        assert _confidence_to_severity(0.90) == "critical"

    def test_080_is_high(self):
        assert _confidence_to_severity(0.80) == "high"

    def test_060_is_medium(self):
        assert _confidence_to_severity(0.60) == "medium"

    def test_040_is_low(self):
        assert _confidence_to_severity(0.40) == "low"


class TestSOCNotificationSystem:
    def setup_method(self):
        self.notifier = SOCNotificationSystem()

    def test_prediction_alert_has_required_fields(self):
        notif = self.notifier.prediction_alert(PREDICTION)
        for field in ("notification_type", "title", "body", "severity", "read", "asset_ids", "evidence", "created_at"):
            assert field in notif, f"Missing: {field}"

    def test_prediction_alert_type(self):
        notif = self.notifier.prediction_alert(PREDICTION)
        assert notif["notification_type"] == "prediction_alert"

    def test_prediction_alert_read_is_false(self):
        notif = self.notifier.prediction_alert(PREDICTION)
        assert notif["read"] is False

    def test_prediction_alert_contains_confidence(self):
        notif = self.notifier.prediction_alert(PREDICTION)
        assert "85%" in notif["body"] or "0.85" in notif["body"]

    def test_attack_confirmed_type(self):
        notif = self.notifier.attack_confirmed(INCIDENT)
        assert notif["notification_type"] == "attack_confirmed"

    def test_attack_confirmed_severity_matches(self):
        notif = self.notifier.attack_confirmed(INCIDENT)
        assert notif["severity"] == "high"

    def test_preemptive_action_type(self):
        notif = self.notifier.preemptive_action_taken(ACTION, PREDICTION)
        assert notif["notification_type"] == "preemptive_action_taken"

    def test_preemptive_action_body_contains_action(self):
        notif = self.notifier.preemptive_action_taken(ACTION, PREDICTION)
        assert "rate_limit_ip" in notif["body"] or "rate limit" in notif["body"].lower() or "host-01" in notif["body"]

    def test_briefing_ready_type(self):
        narrative = {
            "headline": "Test attack",
            "severity_assessment": "High",
            "likely_objective": "Data theft",
        }
        notif = self.notifier.briefing_ready(narrative, "src-123")
        assert notif["notification_type"] == "briefing_ready"

    def test_build_method_returns_dict_with_all_fields(self):
        notif = self.notifier.build(
            notification_type="test",
            title="Test Title",
            body="Test body",
            severity="medium",
            asset_ids=["asset-1"],
            evidence={"key": "value"},
        )
        assert notif["notification_type"] == "test"
        assert notif["title"] == "Test Title"
        assert notif["asset_ids"] == ["asset-1"]
        assert notif["evidence"] == {"key": "value"}


class TestSSEBroadcast:
    @pytest.mark.asyncio
    async def test_broadcast_delivers_to_subscriber(self):
        sub_id = "test-sub-001"
        q = register_subscriber(sub_id)

        notification = {"type": "test", "message": "hello"}
        await broadcast(notification)

        received = await asyncio.wait_for(q.get(), timeout=1.0)
        assert received == notification

        unregister_subscriber(sub_id)

    @pytest.mark.asyncio
    async def test_broadcast_with_no_subscribers_does_not_crash(self):
        # Should complete without error even with no subscribers
        await broadcast({"type": "test"})

    @pytest.mark.asyncio
    async def test_multiple_subscribers_all_receive(self):
        queues = {}
        for i in range(3):
            sub_id = f"sub-{i}"
            queues[sub_id] = register_subscriber(sub_id)

        notification = {"type": "multi", "data": "broadcast"}
        await broadcast(notification)

        for sub_id, q in queues.items():
            received = await asyncio.wait_for(q.get(), timeout=1.0)
            assert received == notification
            unregister_subscriber(sub_id)

    @pytest.mark.asyncio
    async def test_unregister_removes_subscriber(self):
        sub_id = "sub-to-remove"
        register_subscriber(sub_id)
        unregister_subscriber(sub_id)

        # After unregister, broadcast should not deliver to this sub
        # (queue is gone, no error)
        await broadcast({"type": "test"})
