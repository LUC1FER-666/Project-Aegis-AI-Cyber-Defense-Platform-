"""
Preemptive Action Engine
Executes hardening actions when a prediction exceeds the confidence threshold.
All actions are simulated but produce realistic structured output.
"""
from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from app import kafka

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


# Map threat_type → list of action_types to execute
THREAT_ACTION_MAP: dict[str, list[str]] = {
    "brute_force_imminent": ["rate_limit_ip", "alert_soc"],
    "dns_tunnel_imminent": ["enable_dns_inspection", "alert_soc"],
    "c2_beacon_imminent": ["isolate_asset_preemptively", "alert_soc"],
    "account_compromise": ["force_mfa_challenge", "lock_account_temporarily", "alert_soc"],
    "lateral_spread_imminent": ["segment_network", "alert_soc"],
}


class PreemptiveActionEngine:

    async def execute_for_prediction(
        self, prediction: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Execute all appropriate actions for a prediction. Never raises."""
        threat_type = prediction.get("threat_type", "unknown")
        action_types = THREAT_ACTION_MAP.get(threat_type, ["alert_soc"])
        prediction_id = prediction.get("prediction_id", "unknown")
        affected_assets = prediction.get("affected_assets") or []
        confidence = float(prediction.get("confidence", 0.0))

        results = []
        for action_type in action_types:
            result = await self._execute_action(
                action_type=action_type,
                prediction_id=prediction_id,
                affected_assets=affected_assets,
                confidence=confidence,
                prediction=prediction,
            )
            results.append(result)
            logger.info(
                "Preemptive action %s → %s (confidence=%.2f)",
                action_type, result["status"], confidence,
            )
        return results

    async def _execute_action(
        self,
        action_type: str,
        prediction_id: str,
        affected_assets: list[str],
        confidence: float,
        prediction: dict[str, Any],
    ) -> dict[str, Any]:
        start = time.monotonic()
        action_id = str(uuid.uuid4())
        target = affected_assets[0] if affected_assets else "global"

        try:
            handler = {
                "rate_limit_ip": self._rate_limit_ip,
                "enable_dns_inspection": self._enable_dns_inspection,
                "isolate_asset_preemptively": self._isolate_asset_preemptively,
                "force_mfa_challenge": self._force_mfa_challenge,
                "lock_account_temporarily": self._lock_account_temporarily,
                "alert_soc": self._alert_soc,
                "segment_network": self._segment_network,
            }.get(action_type)

            if handler is None:
                result_data: dict[str, Any] = {"error": f"Unknown action: {action_type}"}
                status = "skipped"
            else:
                result_data = await handler(prediction, affected_assets)
                status = "executed"

        except Exception as exc:
            logger.error("Preemptive action %s failed: %s", action_type, exc)
            result_data = {"error": str(exc)}
            status = "failed"

        return {
            "action_id": action_id,
            "action_type": action_type,
            "target": target,
            "status": status,
            "result_data": result_data,
            "confidence_trigger": confidence,
            "prediction_id": prediction_id,
            "executed_at": _now_iso(),
            "duration_ms": _ms(start),
            "rationale": f"Triggered by {prediction.get('threat_type')} prediction (confidence={confidence:.0%})",
        }

    async def _rate_limit_ip(self, prediction: dict[str, Any], assets: list[str]) -> dict[str, Any]:
        evidence = prediction.get("evidence_summary", "")
        # Extract IP from evidence summary
        import re
        ip_match = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", evidence)
        target_ip = ip_match.group() if ip_match else "0.0.0.0"
        rule_id = f"RL-{uuid.uuid4().hex[:8].upper()}"

        await kafka.publish("aegis.response.executed", {
            "action": "rate_limit_ip",
            "target_ip": target_ip,
            "rule_id": rule_id,
            "rate": "10/minute",
            "prediction_id": prediction.get("prediction_id"),
        })
        return {"blocked_ip": target_ip, "rule_id": rule_id, "rate_limit": "10/minute", "applied_at": _now_iso()}

    async def _enable_dns_inspection(self, prediction: dict[str, Any], assets: list[str]) -> dict[str, Any]:
        policy_id = f"DNS-INSP-{uuid.uuid4().hex[:6].upper()}"
        await kafka.publish("aegis.response.executed", {
            "action": "enable_dns_inspection",
            "policy_id": policy_id,
            "prediction_id": prediction.get("prediction_id"),
        })
        return {"policy_id": policy_id, "mode": "deep_inspection", "enabled_at": _now_iso()}

    async def _isolate_asset_preemptively(self, prediction: dict[str, Any], assets: list[str]) -> dict[str, Any]:
        asset = assets[0] if assets else "unknown"
        await kafka.publish("aegis.response.executed", {
            "action": "preemptive_isolation",
            "asset_id": asset,
            "prediction_id": prediction.get("prediction_id"),
        })
        return {"asset_id": asset, "isolation_type": "preemptive", "network_segment": "quarantine-vlan-99", "isolated_at": _now_iso()}

    async def _force_mfa_challenge(self, prediction: dict[str, Any], assets: list[str]) -> dict[str, Any]:
        challenge_id = f"MFA-{uuid.uuid4().hex[:8].upper()}"
        await kafka.publish("aegis.response.executed", {
            "action": "force_mfa_challenge",
            "challenge_id": challenge_id,
            "affected_assets": assets,
            "prediction_id": prediction.get("prediction_id"),
        })
        return {"challenge_id": challenge_id, "scope": "all_active_sessions", "triggered_at": _now_iso()}

    async def _lock_account_temporarily(self, prediction: dict[str, Any], assets: list[str]) -> dict[str, Any]:
        lock_id = f"LOCK-{uuid.uuid4().hex[:8].upper()}"
        await kafka.publish("aegis.response.executed", {
            "action": "lock_account_temporarily",
            "lock_id": lock_id,
            "duration_minutes": 30,
            "prediction_id": prediction.get("prediction_id"),
        })
        return {"lock_id": lock_id, "duration_minutes": 30, "auto_unlock_at": _now_iso()}

    async def _alert_soc(self, prediction: dict[str, Any], assets: list[str]) -> dict[str, Any]:
        notification_id = f"SOC-{uuid.uuid4().hex[:8].upper()}"
        await kafka.publish("aegis.response.proposed", {
            "type": "prediction_alert",
            "notification_id": notification_id,
            "threat_type": prediction.get("threat_type"),
            "confidence": prediction.get("confidence"),
            "affected_assets": assets,
            "evidence": prediction.get("evidence_summary"),
        })
        return {
            "notification_id": notification_id,
            "channel": "soc_dashboard",
            "recipients": ["soc-team@company.com"],
            "sent_at": _now_iso(),
        }

    async def _segment_network(self, prediction: dict[str, Any], assets: list[str]) -> dict[str, Any]:
        segment_id = f"SEG-{uuid.uuid4().hex[:8].upper()}"
        await kafka.publish("aegis.response.executed", {
            "action": "network_segmentation",
            "segment_id": segment_id,
            "isolated_assets": assets,
            "prediction_id": prediction.get("prediction_id"),
        })
        return {"segment_id": segment_id, "isolated_assets": assets, "vlan": "isolation-vlan-100", "applied_at": _now_iso()}
