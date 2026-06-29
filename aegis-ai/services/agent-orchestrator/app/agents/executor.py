"""
Action Executor
All actions are simulated but produce realistic structured output.
Every result includes: action_id, action_type, target, status, result_data, duration_ms, executed_at.
"""
from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from app.agents.playbooks import ActionStep
from app.config import get_settings

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _ms_since(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


class ActionExecutor:
    """Executes ActionSteps for a given incident context."""

    def __init__(self) -> None:
        self.settings = get_settings()

    # ── Dispatcher ───────────────────────────────────────────────────────────

    async def execute(
        self, step: ActionStep, incident: dict[str, Any]
    ) -> dict[str, Any]:
        action_id = str(uuid.uuid4())
        start = time.monotonic()
        target = step.target or step.parameters.get("incident_id", "unknown")

        try:
            handler = {
                "block_ip": self._block_ip,
                "isolate_host": self._isolate_host,
                "kill_process": self._kill_process,
                "collect_logs": self._collect_logs,
                "notify_soc": self._notify_soc,
                "force_password_reset": self._force_password_reset,
                "escalate_to_analyst": self._escalate_to_analyst,
                "enrich_asset": self._enrich_asset,
            }.get(step.action_type)

            if handler is None:
                logger.warning("Unknown action type: %s", step.action_type)
                result_data = {"error": f"Unknown action type: {step.action_type}"}
                status = "skipped"
            else:
                result_data = await handler(step, incident)
                status = "success"

        except Exception as exc:
            logger.error("Action %s failed: %s", step.action_type, exc)
            result_data = {"error": str(exc)}
            status = "failed"

        return {
            "action_id": action_id,
            "action_type": step.action_type,
            "target": target,
            "status": status,
            "result_data": result_data,
            "duration_ms": _ms_since(start),
            "executed_at": _now_iso(),
        }

    # ── Action handlers ──────────────────────────────────────────────────────

    async def _block_ip(
        self, step: ActionStep, incident: dict[str, Any]
    ) -> dict[str, Any]:
        """Extract src_ip from incident evidence and simulate firewall block."""
        evidence = incident.get("evidence") or incident.get("extra_data") or {}
        if isinstance(evidence, list):
            evidence = evidence[0] if evidence else {}

        src_ip = (
            evidence.get("src_ip")
            or evidence.get("source_ip")
            or incident.get("src_ip")
            or "0.0.0.0"
        )
        rule_id = f"FW-BLOCK-{uuid.uuid4().hex[:8].upper()}"

        logger.info("Simulating IP block: %s (rule %s)", src_ip, rule_id)
        return {
            "blocked_ip": src_ip,
            "rule_id": rule_id,
            "firewall": "edge-fw-01",
            "action": "DROP",
            "applied_at": _now_iso(),
        }

    async def _isolate_host(
        self, step: ActionStep, incident: dict[str, Any]
    ) -> dict[str, Any]:
        """Mark asset as isolated (simulated — would update DB in production)."""
        asset_ids: list[str] = (
            step.parameters.get("asset_ids")
            or incident.get("asset_ids")
            or []
        )
        primary_asset = asset_ids[0] if asset_ids else step.target or "unknown"
        isolation_time = _now_iso()

        logger.info("Simulating host isolation: %s", primary_asset)
        return {
            "asset_id": primary_asset,
            "isolation_time": isolation_time,
            "network_segment": "quarantine-vlan-99",
            "method": "vlan_reassignment",
        }

    async def _kill_process(
        self, step: ActionStep, incident: dict[str, Any]
    ) -> dict[str, Any]:
        """Extract process name from evidence and simulate kill."""
        evidence = incident.get("evidence") or {}
        if isinstance(evidence, list):
            evidence = evidence[0] if evidence else {}

        process_name = (
            evidence.get("process_name")
            or evidence.get("process")
            or incident.get("process_name")
            or "suspicious.exe"
        )
        pid = evidence.get("pid") or 9999

        logger.info("Simulating process kill: %s (PID %s)", process_name, pid)
        return {
            "pid": pid,
            "process_name": process_name,
            "signal": "SIGKILL",
            "host": step.target or "unknown-host",
            "killed_at": _now_iso(),
        }

    async def _collect_logs(
        self, step: ActionStep, incident: dict[str, Any]
    ) -> dict[str, Any]:
        """Query Elasticsearch for last 100 logs from asset (simulated)."""
        asset_ids: list[str] = (
            step.parameters.get("asset_ids")
            or incident.get("asset_ids")
            or []
        )
        asset_id = asset_ids[0] if asset_ids else step.target or "unknown"

        # In production, this would call Elasticsearch; here we simulate
        log_count = 47  # realistic-looking simulated result
        logger.info("Simulating log collection for asset: %s", asset_id)
        return {
            "asset_id": asset_id,
            "log_count": log_count,
            "time_range": {
                "from": "2024-01-01T00:00:00Z",
                "to": _now_iso(),
            },
            "sample": [
                f"[SIMULATED] auth failure for root from 192.168.1.{i}"
                for i in range(1, 4)
            ],
            "collection_method": "elasticsearch_query",
        }

    async def _notify_soc(
        self, step: ActionStep, incident: dict[str, Any]
    ) -> dict[str, Any]:
        """Format and publish SOC notification (simulated)."""
        notification_id = f"NOTIF-{uuid.uuid4().hex[:8].upper()}"
        severity = incident.get("severity", "medium")
        title = incident.get("title") or incident.get("incident_title") or "Security Incident"

        recipients = ["soc-team@company.com", "security-manager@company.com"]
        if severity == "critical":
            recipients.append("ciso@company.com")

        logger.info("Simulating SOC notification: %s", notification_id)
        return {
            "notification_id": notification_id,
            "channel": "email+slack",
            "recipients": recipients,
            "subject": f"[{severity.upper()}] {title}",
            "sent_at": _now_iso(),
        }

    async def _force_password_reset(
        self, step: ActionStep, incident: dict[str, Any]
    ) -> dict[str, Any]:
        """Extract affected users from incident and simulate password reset."""
        evidence = incident.get("evidence") or {}
        if isinstance(evidence, list):
            evidence = evidence[0] if evidence else {}

        affected_users: list[str] = (
            incident.get("affected_users")
            or evidence.get("users")
            or evidence.get("usernames")
            or ["admin", "service_account"]
        )
        if isinstance(affected_users, str):
            affected_users = [affected_users]

        reset_tokens = [
            {"user": u, "token": uuid.uuid4().hex, "expires_in": "24h"}
            for u in affected_users
        ]

        logger.info("Simulating password reset for %d user(s)", len(affected_users))
        return {
            "user_list": affected_users,
            "reset_token_count": len(reset_tokens),
            "reset_tokens": reset_tokens,
            "initiated_at": _now_iso(),
        }

    async def _escalate_to_analyst(
        self, step: ActionStep, incident: dict[str, Any]
    ) -> dict[str, Any]:
        """Create manual review record (simulated)."""
        ticket_id = f"TICKET-{uuid.uuid4().hex[:6].upper()}"
        severity = incident.get("severity", "medium")

        priority_map = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}
        priority = priority_map.get(severity.lower(), "P3")

        analysts = {
            "critical": "senior-analyst@company.com",
            "high": "senior-analyst@company.com",
            "medium": "analyst@company.com",
            "low": "junior-analyst@company.com",
        }
        assigned_to = analysts.get(severity.lower(), "analyst@company.com")

        logger.info("Creating escalation ticket: %s (priority %s)", ticket_id, priority)
        return {
            "ticket_id": ticket_id,
            "assigned_to": assigned_to,
            "priority": priority,
            "created_at": _now_iso(),
            "sla_hours": {"P1": 1, "P2": 4, "P3": 8, "P4": 24}.get(priority, 8),
        }

    async def _enrich_asset(
        self, step: ActionStep, incident: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Call asset-discovery service to enrich asset info.
        Returns empty dict on any failure — never propagates the error.
        """
        asset_ids: list[str] = (
            step.parameters.get("asset_ids")
            or incident.get("asset_ids")
            or []
        )
        if not asset_ids:
            return {"enriched": False, "reason": "no asset_ids in incident"}

        asset_id = asset_ids[0]
        base_url = self.settings.asset_discovery_url

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                # Try by asset ID first
                resp = await client.get(
                    f"{base_url}/api/v1/assets/{asset_id}"
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return {"enriched": True, "asset": data}

                # Try by hostname
                hostname = asset_id
                resp2 = await client.get(
                    f"{base_url}/api/v1/assets",
                    params={"hostname": hostname},
                )
                if resp2.status_code == 200:
                    items = resp2.json()
                    if items:
                        return {"enriched": True, "asset": items[0]}

            return {"enriched": False, "reason": "asset not found", "asset_id": asset_id}

        except Exception as exc:
            logger.warning("Asset enrichment failed: %s", exc)
            return {"enriched": False, "reason": str(exc), "asset_id": asset_id}
