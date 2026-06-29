"""
Predictive Threat Monitor
Analyses recent telemetry/alert patterns to predict imminent attacks.
All logic is rule-based — no ML, no external dependencies.
"""
from __future__ import annotations

import logging
import math
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from app.config import get_settings

logger = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = defaultdict(int)
    for c in s:
        freq[c] += 1
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def _make_prediction(
    threat_type: str,
    confidence: float,
    affected_assets: list[str],
    evidence_summary: str,
    predicted_attack_vector: str,
    recommended_actions: list[str],
    ttl_minutes: int = 10,
) -> dict[str, Any]:
    return {
        "prediction_id": f"pred-{uuid.uuid4().hex[:12]}",
        "threat_type": threat_type,
        "confidence": confidence,
        "affected_assets": affected_assets,
        "evidence_summary": evidence_summary,
        "predicted_attack_vector": predicted_attack_vector,
        "recommended_actions": recommended_actions,
        "expires_at": (_now() + timedelta(minutes=ttl_minutes)).isoformat(),
    }


class PredictiveThreatMonitor:
    """
    Analyses event lists for threat patterns and generates predictions.
    Stateless — all state lives in the DB. Designed for pure unit testing.
    """

    def __init__(self, ttl_minutes: int = 10) -> None:
        self.ttl_minutes = ttl_minutes

    def analyze(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Run all detection rules against a list of recent events.
        Returns a list of prediction dicts (not yet persisted).
        """
        predictions: list[dict[str, Any]] = []
        now = _now()

        predictions.extend(self._detect_brute_force(events, now))
        predictions.extend(self._detect_dns_tunnel(events, now))
        predictions.extend(self._detect_c2_beacon(events, now))
        predictions.extend(self._detect_account_compromise(events, now))
        predictions.extend(self._detect_lateral_spread(events, now))

        return predictions

    # ── Rule 1: Brute force ───────────────────────────────────────────────────

    def _detect_brute_force(
        self, events: list[dict[str, Any]], now: datetime
    ) -> list[dict[str, Any]]:
        """3+ auth failures from same IP in last 5 minutes → brute_force_imminent."""
        cutoff = now - timedelta(minutes=5)
        failures: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for e in events:
            ts = self._parse_ts(e.get("timestamp"))
            if ts and ts >= cutoff:
                cat = str(e.get("category", "") or e.get("event_type", "")).lower()
                if cat == "auth" and str(e.get("auth_result", "")).lower() in ("failure", "failed", "false"):
                    src = str(e.get("src_ip") or e.get("source_ip") or "unknown")
                    failures[src].append(e)

        results = []
        for src_ip, evts in failures.items():
            if len(evts) >= 3:
                assets = list({str(e.get("asset_id") or e.get("hostname") or "unknown") for e in evts})
                results.append(_make_prediction(
                    threat_type="brute_force_imminent",
                    confidence=0.85,
                    affected_assets=assets,
                    evidence_summary=f"{len(evts)} auth failures from {src_ip} in last 5 minutes",
                    predicted_attack_vector=f"Credential brute-force from {src_ip}",
                    recommended_actions=["rate_limit_ip", "alert_soc", "enable_account_lockout"],
                    ttl_minutes=self.ttl_minutes,
                ))
        return results

    # ── Rule 2: DNS tunneling ─────────────────────────────────────────────────

    def _detect_dns_tunnel(
        self, events: list[dict[str, Any]], now: datetime
    ) -> list[dict[str, Any]]:
        """DNS queries with entropy > 4.5 in last 2 minutes → dns_tunnel_imminent."""
        cutoff = now - timedelta(minutes=2)
        suspicious: list[dict[str, Any]] = []

        for e in events:
            ts = self._parse_ts(e.get("timestamp"))
            if ts and ts >= cutoff:
                cat = str(e.get("category", "") or e.get("event_type", "")).lower()
                if cat == "dns":
                    query = str(e.get("query") or e.get("dns_query") or "")
                    subdomain = query.split(".")[0] if "." in query else query
                    if _shannon_entropy(subdomain) > 4.2:
                        suspicious.append(e)

        if not suspicious:
            return []

        assets = list({str(e.get("asset_id") or e.get("hostname") or "unknown") for e in suspicious})
        queries = [str(e.get("query") or "") for e in suspicious[:3]]
        return [_make_prediction(
            threat_type="dns_tunnel_imminent",
            confidence=0.80,
            affected_assets=assets,
            evidence_summary=f"{len(suspicious)} high-entropy DNS queries detected: {queries}",
            predicted_attack_vector="DNS tunneling for C2 communication or data exfiltration",
            recommended_actions=["enable_dns_inspection", "alert_soc", "block_suspicious_domains"],
            ttl_minutes=self.ttl_minutes,
        )]

    # ── Rule 3: C2 beacon ─────────────────────────────────────────────────────

    def _detect_c2_beacon(
        self, events: list[dict[str, Any]], now: datetime
    ) -> list[dict[str, Any]]:
        """Process creation + network connection from same asset in 60s → c2_beacon_imminent."""
        cutoff = now - timedelta(seconds=60)
        by_asset: dict[str, dict[str, list]] = defaultdict(lambda: {"process": [], "network": []})

        for e in events:
            ts = self._parse_ts(e.get("timestamp"))
            if not ts or ts < cutoff:
                continue
            asset = str(e.get("asset_id") or e.get("hostname") or "unknown")
            cat = str(e.get("category", "") or e.get("event_type", "")).lower()
            if cat == "process":
                by_asset[asset]["process"].append(e)
            elif cat == "network":
                by_asset[asset]["network"].append(e)

        results = []
        for asset, groups in by_asset.items():
            if groups["process"] and groups["network"]:
                proc = groups["process"][0].get("process_name", "unknown")
                results.append(_make_prediction(
                    threat_type="c2_beacon_imminent",
                    confidence=0.75,
                    affected_assets=[asset],
                    evidence_summary=f"Process '{proc}' spawned and made network connection within 60s on {asset}",
                    predicted_attack_vector="Malware establishing C2 communication channel",
                    recommended_actions=["isolate_asset_preemptively", "alert_soc", "collect_process_tree"],
                    ttl_minutes=self.ttl_minutes,
                ))
        return results

    # ── Rule 4: Account compromise ────────────────────────────────────────────

    def _detect_account_compromise(
        self, events: list[dict[str, Any]], now: datetime
    ) -> list[dict[str, Any]]:
        """Auth success after 2+ failures from same IP → account_compromise."""
        cutoff = now - timedelta(minutes=10)
        by_ip: dict[str, dict[str, list]] = defaultdict(lambda: {"failures": [], "successes": []})

        for e in events:
            ts = self._parse_ts(e.get("timestamp"))
            if not ts or ts < cutoff:
                continue
            cat = str(e.get("category", "") or e.get("event_type", "")).lower()
            if cat != "auth":
                continue
            src = str(e.get("src_ip") or e.get("source_ip") or "unknown")
            result = str(e.get("auth_result", "")).lower()
            if result in ("failure", "failed", "false"):
                by_ip[src]["failures"].append(e)
            elif result in ("success", "true"):
                by_ip[src]["successes"].append(e)

        results = []
        for src_ip, groups in by_ip.items():
            if len(groups["failures"]) >= 2 and groups["successes"]:
                users = list({str(e.get("username") or e.get("user") or "unknown") for e in groups["successes"]})
                assets = list({str(e.get("asset_id") or e.get("hostname") or "unknown") for e in groups["successes"]})
                results.append(_make_prediction(
                    threat_type="account_compromise",
                    confidence=0.90,
                    affected_assets=assets,
                    evidence_summary=f"Auth success from {src_ip} after {len(groups['failures'])} failures. Users: {users}",
                    predicted_attack_vector=f"Compromised credentials for {users} from {src_ip}",
                    recommended_actions=["force_mfa_challenge", "lock_account_temporarily", "alert_soc"],
                    ttl_minutes=self.ttl_minutes,
                ))
        return results

    # ── Rule 5: Lateral spread ────────────────────────────────────────────────

    def _detect_lateral_spread(
        self, events: list[dict[str, Any]], now: datetime
    ) -> list[dict[str, Any]]:
        """Same MITRE technique on 3+ assets in 10 minutes → lateral_spread_imminent."""
        cutoff = now - timedelta(minutes=10)
        by_technique: dict[str, set] = defaultdict(set)

        for e in events:
            ts = self._parse_ts(e.get("timestamp"))
            if not ts or ts < cutoff:
                continue
            technique = str(e.get("mitre_technique") or e.get("technique_id") or "")
            if not technique:
                continue
            asset = str(e.get("asset_id") or e.get("hostname") or "unknown")
            by_technique[technique].add(asset)

        results = []
        for technique, assets in by_technique.items():
            if len(assets) >= 3:
                results.append(_make_prediction(
                    threat_type="lateral_spread_imminent",
                    confidence=0.88,
                    affected_assets=list(assets),
                    evidence_summary=f"Technique {technique} observed on {len(assets)} assets in last 10 minutes",
                    predicted_attack_vector=f"Active lateral movement using {technique}",
                    recommended_actions=["segment_network", "alert_soc", "isolate_affected_assets"],
                    ttl_minutes=self.ttl_minutes,
                ))
        return results

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_ts(val: Any) -> datetime | None:
        if val is None:
            return None
        if isinstance(val, datetime):
            if val.tzinfo is None:
                return val.replace(tzinfo=timezone.utc)
            return val
        try:
            dt = datetime.fromisoformat(str(val).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError):
            return None
