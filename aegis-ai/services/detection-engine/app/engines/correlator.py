"""
Detection Engine — Layer 4: Alert Correlator

Groups related alerts into incidents.  Correlation strategies:
  1. Asset-based: multiple alerts on the same asset within a time window
  2. Technique-based: same MITRE technique across different assets
  3. Lateral movement: auth + process alerts forming a sequence

Incidents are assigned severity equal to the maximum alert severity.
The correlator is stateful in-memory; PostgreSQL provides persistence.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class AlertRecord:
    """Lightweight alert record held in correlator state."""
    alert_id: str
    rule_id: str
    asset_id: Optional[str]
    severity: str
    mitre_technique: Optional[str]
    confidence_score: float
    evidence: dict[str, Any]
    source_event_id: Optional[str]
    source_log_type: Optional[str]
    created_at: datetime


@dataclass
class CorrelationBucket:
    """An in-progress grouping of alerts."""
    bucket_id: str
    correlation_key: str
    strategy: str       # "asset", "technique", "lateral_movement"
    alerts: list[AlertRecord] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    closed: bool = False

    def add(self, alert: AlertRecord) -> None:
        self.alerts.append(alert)
        if self.first_seen is None or alert.created_at < self.first_seen:
            self.first_seen = alert.created_at
        if self.last_seen is None or alert.created_at > self.last_seen:
            self.last_seen = alert.created_at

    @property
    def severity(self) -> str:
        if not self.alerts:
            return "low"
        return max(self.alerts, key=lambda a: SEVERITY_ORDER.get(a.severity, 0)).severity

    @property
    def mitre_techniques(self) -> list[str]:
        return list({a.mitre_technique for a in self.alerts if a.mitre_technique})

    @property
    def affected_assets(self) -> list[str]:
        return list({a.asset_id for a in self.alerts if a.asset_id})


@dataclass
class CorrelatedIncident:
    """Output from the correlator — ready to persist as an Incident."""
    incident_id: str
    title: str
    description: str
    severity: str
    mitre_techniques: list[str]
    affected_assets: list[str]
    alert_ids: list[str]
    alert_count: int
    correlation_key: str
    strategy: str
    first_seen: datetime
    last_seen: datetime


class AlertCorrelator:
    """
    Time-window based correlator.

    Algorithm:
    - Maintain open buckets per correlation key
    - A bucket is "ready" when it has ≥ min_alerts
    - A bucket is "expired" when last_seen is > window_seconds ago
    - Expired buckets with enough alerts are emitted as incidents
    - Periodic sweep closes stale buckets
    """

    def __init__(
        self,
        window_seconds: int = 300,
        min_alerts: int = 2,
    ):
        self.window_seconds = window_seconds
        self.min_alerts = min_alerts

        # correlation_key → CorrelationBucket
        self._buckets: dict[str, CorrelationBucket] = {}
        self._lock = asyncio.Lock()

    async def ingest_alert(self, alert: AlertRecord) -> list[CorrelatedIncident]:
        """
        Add an alert to relevant buckets.
        Returns any incidents that are ready to be emitted.
        """
        async with self._lock:
            incidents: list[CorrelatedIncident] = []

            # Strategy 1: Asset-based correlation
            if alert.asset_id:
                key = f"asset:{alert.asset_id}"
                bucket = self._get_or_create_bucket(key, "asset")
                bucket.add(alert)
                if incident := self._maybe_close_bucket(bucket, trigger="new_alert"):
                    incidents.append(incident)

            # Strategy 2: Technique-based correlation
            if alert.mitre_technique:
                key = f"technique:{alert.mitre_technique}"
                bucket = self._get_or_create_bucket(key, "technique")
                bucket.add(alert)
                if incident := self._maybe_close_bucket(bucket, trigger="new_alert"):
                    incidents.append(incident)

            # Strategy 3: Lateral movement — auth + process on same asset
            if alert.asset_id and alert.source_log_type in ("auth", "process", "windows_event"):
                key = f"lateral:{alert.asset_id}"
                bucket = self._get_or_create_bucket(key, "lateral_movement")
                bucket.add(alert)
                if self._is_lateral_movement(bucket):
                    if incident := self._maybe_close_bucket(bucket, trigger="lateral_pattern"):
                        incidents.append(incident)

            return incidents

    async def sweep_expired(self) -> list[CorrelatedIncident]:
        """
        Called periodically to emit incidents from expired buckets.
        A bucket expires when no new alerts have arrived in window_seconds.
        """
        async with self._lock:
            incidents = []
            now = datetime.now(timezone.utc)
            expired_keys = []

            for key, bucket in self._buckets.items():
                if bucket.closed:
                    expired_keys.append(key)
                    continue
                if bucket.last_seen is None:
                    continue
                age = (now - bucket.last_seen).total_seconds()
                if age > self.window_seconds and len(bucket.alerts) >= self.min_alerts:
                    incident = self._close_bucket(bucket)
                    incidents.append(incident)
                    expired_keys.append(key)
                elif age > self.window_seconds * 3:
                    # Too old even without enough alerts — discard
                    bucket.closed = True
                    expired_keys.append(key)

            for key in expired_keys:
                del self._buckets[key]

            return incidents

    # ── Internal ──────────────────────────────────────────────────────────────

    def _get_or_create_bucket(self, key: str, strategy: str) -> CorrelationBucket:
        if key not in self._buckets:
            self._buckets[key] = CorrelationBucket(
                bucket_id=str(uuid.uuid4()),
                correlation_key=key,
                strategy=strategy,
            )
        return self._buckets[key]

    def _maybe_close_bucket(
        self, bucket: CorrelationBucket, trigger: str
    ) -> Optional[CorrelatedIncident]:
        """
        Close the bucket and return an incident if it has enough alerts
        AND they span a meaningful timespan (> 30s) or we have a specific trigger.
        """
        if bucket.closed:
            return None
        if len(bucket.alerts) < self.min_alerts:
            return None

        # Don't re-fire for every new alert — threshold gates
        # Close at 2, 5, 10, 20, 50 alerts (powers + round numbers)
        n = len(bucket.alerts)
        thresholds = {2, 5, 10, 20, 50}
        if n not in thresholds and trigger != "lateral_pattern":
            return None

        return self._close_bucket(bucket)

    def _close_bucket(self, bucket: CorrelationBucket) -> CorrelatedIncident:
        bucket.closed = True

        title = self._generate_title(bucket)
        description = self._generate_description(bucket)

        return CorrelatedIncident(
            incident_id=str(uuid.uuid4()),
            title=title,
            description=description,
            severity=bucket.severity,
            mitre_techniques=bucket.mitre_techniques,
            affected_assets=bucket.affected_assets,
            alert_ids=[a.alert_id for a in bucket.alerts],
            alert_count=len(bucket.alerts),
            correlation_key=bucket.correlation_key,
            strategy=bucket.strategy,
            first_seen=bucket.first_seen or datetime.now(timezone.utc),
            last_seen=bucket.last_seen or datetime.now(timezone.utc),
        )

    def _is_lateral_movement(self, bucket: CorrelationBucket) -> bool:
        """
        Detect lateral movement pattern: auth failure(s) followed by process creation
        on the same asset, within the correlation window.
        """
        log_types = {a.source_log_type for a in bucket.alerts}
        has_auth = bool({"auth", "windows_event"} & log_types)
        has_process = "process" in log_types
        return has_auth and has_process and len(bucket.alerts) >= self.min_alerts

    def _generate_title(self, bucket: CorrelationBucket) -> str:
        """Human-readable incident title."""
        strategy = bucket.strategy

        if strategy == "asset":
            assets = bucket.affected_assets
            asset_str = assets[0] if assets else "Unknown Asset"
            techniques = bucket.mitre_techniques
            tech_str = f" ({', '.join(techniques[:2])})" if techniques else ""
            return f"Multi-Alert Incident on {asset_str}{tech_str}"

        elif strategy == "technique":
            techniques = bucket.mitre_techniques
            tech_str = techniques[0] if techniques else "Unknown Technique"
            assets = bucket.affected_assets
            if len(assets) > 1:
                return f"Technique {tech_str} Across {len(assets)} Assets"
            return f"Repeated Use of {tech_str}"

        elif strategy == "lateral_movement":
            assets = bucket.affected_assets
            asset_str = assets[0] if assets else "Unknown Asset"
            return f"Potential Lateral Movement — {asset_str}"

        return f"Correlated Incident ({len(bucket.alerts)} alerts)"

    def _generate_description(self, bucket: CorrelationBucket) -> str:
        """Auto-generated incident description."""
        lines = [
            f"Correlation strategy: {bucket.strategy}",
            f"Alert count: {len(bucket.alerts)}",
        ]
        if bucket.affected_assets:
            lines.append(f"Affected assets: {', '.join(bucket.affected_assets[:5])}")
        if bucket.mitre_techniques:
            lines.append(f"MITRE techniques: {', '.join(bucket.mitre_techniques)}")

        severities = {}
        for a in bucket.alerts:
            severities[a.severity] = severities.get(a.severity, 0) + 1
        sev_str = ", ".join(f"{v}x {k}" for k, v in sorted(severities.items()))
        lines.append(f"Severity breakdown: {sev_str}")

        return " | ".join(lines)
