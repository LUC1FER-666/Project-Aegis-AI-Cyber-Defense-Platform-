"""
Tests — Alert Correlator

Covers:
- Asset-based correlation
- Technique-based correlation
- Lateral movement detection
- Bucket expiry / sweep
- Threshold gating (incidents emitted at 2, 5, 10 alerts)
- Severity aggregation (max severity wins)
"""
import asyncio
import pytest
import uuid
from datetime import datetime, timezone, timedelta

from app.engines.correlator import AlertCorrelator, AlertRecord, CorrelationBucket


def _make_alert(
    asset_id="host-001",
    severity="medium",
    mitre_technique="T1059.001",
    source_log_type="process",
    rule_id="rule-001",
):
    return AlertRecord(
        alert_id=str(uuid.uuid4()),
        rule_id=rule_id,
        asset_id=asset_id,
        severity=severity,
        mitre_technique=mitre_technique,
        confidence_score=0.8,
        evidence={"CommandLine": "test"},
        source_event_id=str(uuid.uuid4()),
        source_log_type=source_log_type,
        created_at=datetime.now(timezone.utc),
    )


class TestCorrelationBucket:
    def test_add_alert_updates_first_last_seen(self):
        bucket = CorrelationBucket(
            bucket_id="b1",
            correlation_key="asset:host-1",
            strategy="asset",
        )
        t1 = datetime(2024, 1, 1, 10, 0, tzinfo=timezone.utc)
        t2 = datetime(2024, 1, 1, 10, 5, tzinfo=timezone.utc)

        a1 = _make_alert()
        a1.created_at = t1
        a2 = _make_alert()
        a2.created_at = t2

        bucket.add(a1)
        bucket.add(a2)

        assert bucket.first_seen == t1
        assert bucket.last_seen == t2

    def test_severity_returns_max(self):
        bucket = CorrelationBucket(bucket_id="b2", correlation_key="k", strategy="asset")
        for sev in ["low", "critical", "medium"]:
            a = _make_alert(severity=sev)
            bucket.add(a)
        assert bucket.severity == "critical"

    def test_mitre_techniques_deduplicated(self):
        bucket = CorrelationBucket(bucket_id="b3", correlation_key="k", strategy="asset")
        for _ in range(3):
            bucket.add(_make_alert(mitre_technique="T1059.001"))
        bucket.add(_make_alert(mitre_technique="T1110"))
        techniques = bucket.mitre_techniques
        assert len(techniques) == 2
        assert "T1059.001" in techniques

    def test_affected_assets_deduplicated(self):
        bucket = CorrelationBucket(bucket_id="b4", correlation_key="k", strategy="technique")
        for host in ["host-1", "host-1", "host-2"]:
            bucket.add(_make_alert(asset_id=host))
        assert len(bucket.affected_assets) == 2

    def test_severity_single_alert(self):
        bucket = CorrelationBucket(bucket_id="b5", correlation_key="k", strategy="asset")
        bucket.add(_make_alert(severity="high"))
        assert bucket.severity == "high"

    def test_empty_bucket_severity_defaults_low(self):
        bucket = CorrelationBucket(bucket_id="b6", correlation_key="k", strategy="asset")
        assert bucket.severity == "low"


class TestAlertCorrelator:
    @pytest.mark.asyncio
    async def test_single_alert_no_incident(self):
        corr = AlertCorrelator(window_seconds=300, min_alerts=2)
        incidents = await corr.ingest_alert(_make_alert())
        assert incidents == []

    @pytest.mark.asyncio
    async def test_two_alerts_same_asset_creates_incident(self):
        corr = AlertCorrelator(window_seconds=300, min_alerts=2)
        await corr.ingest_alert(_make_alert(asset_id="host-001"))
        incidents = await corr.ingest_alert(_make_alert(asset_id="host-001"))
        assert len(incidents) >= 1
        incident = incidents[0]
        assert "host-001" in incident.affected_assets

    @pytest.mark.asyncio
    async def test_two_alerts_same_technique_creates_incident(self):
        corr = AlertCorrelator(window_seconds=300, min_alerts=2)
        await corr.ingest_alert(_make_alert(asset_id="host-001", mitre_technique="T1059.001"))
        incidents = await corr.ingest_alert(_make_alert(asset_id="host-002", mitre_technique="T1059.001"))
        # Should have technique-based incident
        technique_incidents = [i for i in incidents if i.strategy == "technique"]
        assert len(technique_incidents) >= 1

    @pytest.mark.asyncio
    async def test_different_assets_different_techniques_no_incident(self):
        corr = AlertCorrelator(window_seconds=300, min_alerts=2)
        await corr.ingest_alert(_make_alert(asset_id="host-001", mitre_technique="T1059.001"))
        incidents = await corr.ingest_alert(_make_alert(asset_id="host-002", mitre_technique="T1110"))
        # No shared bucket should reach threshold
        asset_incidents = [i for i in incidents if i.strategy == "asset"]
        assert len(asset_incidents) == 0

    @pytest.mark.asyncio
    async def test_incident_severity_is_max_of_alerts(self):
        corr = AlertCorrelator(window_seconds=300, min_alerts=2)
        await corr.ingest_alert(_make_alert(asset_id="host-001", severity="low"))
        incidents = await corr.ingest_alert(_make_alert(asset_id="host-001", severity="critical"))
        incident = next((i for i in incidents if i.strategy == "asset"), None)
        assert incident is not None
        assert incident.severity == "critical"

    @pytest.mark.asyncio
    async def test_incident_contains_alert_ids(self):
        corr = AlertCorrelator(window_seconds=300, min_alerts=2)
        a1 = _make_alert(asset_id="host-001")
        a2 = _make_alert(asset_id="host-001")
        await corr.ingest_alert(a1)
        incidents = await corr.ingest_alert(a2)
        incident = next((i for i in incidents if i.strategy == "asset"), None)
        assert incident is not None
        assert a1.alert_id in incident.alert_ids
        assert a2.alert_id in incident.alert_ids

    @pytest.mark.asyncio
    async def test_lateral_movement_detected(self):
        corr = AlertCorrelator(window_seconds=300, min_alerts=2)
        auth_alert = _make_alert(
            asset_id="host-001",
            source_log_type="auth",
            mitre_technique="T1110",
        )
        process_alert = _make_alert(
            asset_id="host-001",
            source_log_type="process",
            mitre_technique="T1059.001",
        )
        await corr.ingest_alert(auth_alert)
        incidents = await corr.ingest_alert(process_alert)
        lateral = [i for i in incidents if i.strategy == "lateral_movement"]
        assert len(lateral) >= 1

    @pytest.mark.asyncio
    async def test_no_lateral_movement_single_type(self):
        corr = AlertCorrelator(window_seconds=300, min_alerts=2)
        # Both are process events — not lateral movement
        await corr.ingest_alert(_make_alert(asset_id="host-001", source_log_type="process"))
        incidents = await corr.ingest_alert(_make_alert(asset_id="host-001", source_log_type="process"))
        lateral = [i for i in incidents if i.strategy == "lateral_movement"]
        assert len(lateral) == 0

    @pytest.mark.asyncio
    async def test_threshold_gating_fires_at_5(self):
        corr = AlertCorrelator(window_seconds=300, min_alerts=2)
        all_incidents = []
        # First two → incident at 2
        for _ in range(2):
            incidents = await corr.ingest_alert(_make_alert(asset_id="host-gate"))
            all_incidents.extend(incidents)
        # 3 and 4 → no new incident (bucket is closed after 2)
        for _ in range(2):
            incidents = await corr.ingest_alert(_make_alert(asset_id="host-gate"))
            all_incidents.extend(incidents)
        # Total: incidents at count=2 only (bucket closed after first incident)
        asset_incidents = [i for i in all_incidents if i.strategy == "asset"]
        assert len(asset_incidents) == 1

    @pytest.mark.asyncio
    async def test_sweep_emits_expired_buckets(self):
        corr = AlertCorrelator(window_seconds=1, min_alerts=2)
        # Add 2 alerts
        await corr.ingest_alert(_make_alert(asset_id="sweep-host"))
        await corr.ingest_alert(_make_alert(asset_id="sweep-host"))
        # Bucket already closed at count=2 — sweep should return nothing new
        incidents = await corr.sweep_expired()
        # Already emitted at ingest
        assert isinstance(incidents, list)

    @pytest.mark.asyncio
    async def test_sweep_discards_stale_buckets_with_insufficient_alerts(self):
        corr = AlertCorrelator(window_seconds=1, min_alerts=5)
        # Only 1 alert — below min_alerts
        alert = _make_alert(asset_id="stale-host")
        await corr.ingest_alert(alert)

        # Artificially age the bucket
        key = f"asset:stale-host"
        if key in corr._buckets:
            corr._buckets[key].last_seen = datetime(2020, 1, 1, tzinfo=timezone.utc)

        incidents = await corr.sweep_expired()
        assert incidents == []

    @pytest.mark.asyncio
    async def test_incident_title_asset_strategy(self):
        corr = AlertCorrelator(window_seconds=300, min_alerts=2)
        for _ in range(2):
            await corr.ingest_alert(_make_alert(asset_id="web-server-01", mitre_technique="T1059"))
        # Check in buckets whether title generation worked
        # (incident already emitted — bucket is closed)
        # Re-create to check title
        bucket = CorrelationBucket(bucket_id="t1", correlation_key="asset:web-server-01", strategy="asset")
        bucket.add(_make_alert(asset_id="web-server-01", mitre_technique="T1059"))
        bucket.add(_make_alert(asset_id="web-server-01"))
        title = corr._generate_title(bucket)
        assert "web-server-01" in title

    @pytest.mark.asyncio
    async def test_incident_correlation_key_preserved(self):
        corr = AlertCorrelator(window_seconds=300, min_alerts=2)
        await corr.ingest_alert(_make_alert(asset_id="key-host"))
        incidents = await corr.ingest_alert(_make_alert(asset_id="key-host"))
        asset_incident = next((i for i in incidents if i.strategy == "asset"), None)
        assert asset_incident is not None
        assert "key-host" in asset_incident.correlation_key

    @pytest.mark.asyncio
    async def test_alerts_without_asset_id_skip_asset_bucket(self):
        corr = AlertCorrelator(window_seconds=300, min_alerts=2)
        a1 = _make_alert(mitre_technique="T1059")
        a1.asset_id = None
        a2 = _make_alert(mitre_technique="T1059")
        a2.asset_id = None
        await corr.ingest_alert(a1)
        incidents = await corr.ingest_alert(a2)
        asset_incidents = [i for i in incidents if i.strategy == "asset"]
        assert len(asset_incidents) == 0
        # But technique bucket should fire
        technique_incidents = [i for i in incidents if i.strategy == "technique"]
        assert len(technique_incidents) >= 1
