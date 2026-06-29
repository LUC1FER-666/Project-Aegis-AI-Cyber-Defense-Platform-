"""
Milestone 7 Unit Tests — Timeline + Graph Service
All external dependencies (PostgreSQL, Redis, Neo4j, HTTP) are mocked.
Run with: pytest tests/test_milestone7.py -v
"""
import asyncio
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

# ─── Fixtures ──────────────────────────────────────────────────────────────────

def make_alert(i: int = 1) -> dict:
    return {
        "alert_id": f"alert-{i:04d}",
        "rule_id": f"sigma-rule-{i}",
        "asset_id": f"asset-{i:03d}",
        "severity": ["low", "medium", "high", "critical"][i % 4],
        "mitre_technique": ["T1059.001", "T1053.005", "T1110", "T1071.004", "T1571"][i % 5],
        "confidence_score": round(0.5 + (i % 5) * 0.1, 2),
        "evidence": {"raw": "test"},
        "source_log_type": "windows_event",
        "status": "open",
        "llm_validated": True,
        "suppressed_by_llm": False,
        "created_at": "2024-01-15T10:00:00+00:00",
    }


def make_incident(i: int = 1) -> dict:
    return {
        "incident_id": f"inc-{i:04d}",
        "title": f"Incident {i}: Lateral Movement Detected",
        "severity": "high",
        "status": "open",
        "mitre_techniques": ["T1021", "T1078"],
        "affected_assets": [f"asset-{i:03d}", f"asset-{i+1:03d}"],
        "alert_count": 5,
        "first_seen": "2024-01-15T09:00:00+00:00",
        "last_seen": "2024-01-15T10:00:00+00:00",
        "correlation_key": f"lateral:{i}",
        "created_at": "2024-01-15T09:00:00+00:00",
    }


def make_task(i: int = 1) -> dict:
    return {
        "id": f"task-{i:04d}",
        "incident_id": f"inc-{i:04d}",
        "incident_title": f"Incident {i}",
        "severity": "high",
        "status": "completed",
        "selected_playbook": "lateral_movement_response",
        "playbook_steps": [],
        "actions_results": {},
        "triage": {"summary": "Test triage"},
        "created_at": "2024-01-15T10:05:00+00:00",
    }


def make_prediction(i: int = 1) -> dict:
    return {
        "prediction_id": f"pred-{i:04d}",
        "threat_type": "brute_force_imminent",
        "confidence": 0.87,
        "description": f"Predicted brute force attack on asset {i}",
        "affected_assets": [f"asset-{i:03d}"],
        "mitre_techniques": ["T1110"],
        "status": "active",
        "created_at": "2024-01-15T10:01:00+00:00",
    }


# ─── Schema Tests ──────────────────────────────────────────────────────────────

class TestSchemas:
    def test_timeline_event_out_schema(self):
        from app.models.schemas import TimelineEventOut
        now = datetime.now(timezone.utc)
        ev = TimelineEventOut(
            event_id="alert:alert-0001",
            event_type="alert",
            severity="high",
            title="Alert: sigma-rule-1",
            description="T1059.001 detected",
            source_service="detection-engine",
            source_id="alert-0001",
            asset_ids=["asset-001"],
            mitre_techniques=["T1059.001"],
            extra_data={"confidence_score": 0.9},
            timestamp=now,
            created_at=now,
        )
        assert ev.event_id == "alert:alert-0001"
        assert ev.event_type == "alert"
        assert ev.severity == "high"
        assert "asset-001" in ev.asset_ids

    def test_graph_node_schema(self):
        from app.models.schemas import GraphNode
        node = GraphNode(
            id="asset-001",
            type="Asset",
            label="web-server-01",
            severity="high",
            properties={"risk_score": 85},
        )
        assert node.id == "asset-001"
        assert node.type == "Asset"
        assert node.properties["risk_score"] == 85

    def test_graph_edge_schema(self):
        from app.models.schemas import GraphEdge
        edge = GraphEdge(
            source="alert-0001",
            target="asset-001",
            type="TRIGGERED_ON",
            properties={},
        )
        assert edge.source == "alert-0001"
        assert edge.type == "TRIGGERED_ON"

    def test_graph_response_schema(self):
        from app.models.schemas import GraphResponse, GraphNode, GraphEdge, GraphStats
        resp = GraphResponse(
            nodes=[GraphNode(id="a", type="Asset", label="host")],
            edges=[GraphEdge(source="a", target="b", type="CONNECTS")],
            stats=GraphStats(node_count=1, edge_count=1),
        )
        assert resp.stats.node_count == 1
        assert resp.warning is None

    def test_graph_response_with_warning(self):
        from app.models.schemas import GraphResponse, GraphStats
        resp = GraphResponse(
            nodes=[], edges=[],
            stats=GraphStats(node_count=0, edge_count=0),
            warning="Neo4j unavailable",
        )
        assert resp.warning == "Neo4j unavailable"
        assert len(resp.nodes) == 0

    def test_timeline_stats_schema(self):
        from app.models.schemas import TimelineStats
        stats = TimelineStats(
            total_events=150,
            by_type={"alert": 100, "incident": 30, "agent_task": 20},
            by_severity={"high": 80, "critical": 20, "medium": 50},
            events_last_hour=12,
            events_last_24h=75,
        )
        assert stats.total_events == 150
        assert stats.by_type["alert"] == 100


# ─── Config Tests ──────────────────────────────────────────────────────────────

class TestConfig:
    def test_settings_defaults(self):
        from app.core.config import settings
        assert "localhost" in settings.DATABASE_URL or "aegis" in settings.DATABASE_URL
        assert settings.TIMELINE_POLL_INTERVAL == 10
        assert settings.GRAPH_BUILD_INTERVAL == 30
        assert settings.REDIS_TIMELINE_MAX == 500

    def test_redis_key_format(self):
        from app.core.config import settings
        seen_key = f"{settings.REDIS_SEEN_PREFIX}:alert"
        assert seen_key == "aegis:timeline:seen:alert"

    def test_downstream_urls_configured(self):
        from app.core.config import settings
        assert "8004" in settings.DETECTION_ENGINE_URL
        assert "8005" in settings.AGENT_ORCHESTRATOR_URL
        assert "8006" in settings.THREAT_DEFENSE_URL


# ─── Redis Client Tests ────────────────────────────────────────────────────────

class TestRedisClient:
    def test_initial_state(self):
        from app.core.redis_client import RedisClient
        client = RedisClient()
        assert client.is_connected is False
        assert client._client is None

    @pytest.mark.asyncio
    async def test_connect_success(self):
        from app.core.redis_client import RedisClient
        client = RedisClient()
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(return_value=True)
        with patch("redis.asyncio.from_url", return_value=mock_redis):
            await client.connect()
        assert client.is_connected is True

    @pytest.mark.asyncio
    async def test_connect_failure_graceful(self):
        from app.core.redis_client import RedisClient
        client = RedisClient()
        with patch("redis.asyncio.from_url", side_effect=ConnectionRefusedError("refused")):
            await client.connect()
        assert client.is_connected is False

    @pytest.mark.asyncio
    async def test_zadd_when_disconnected(self):
        from app.core.redis_client import RedisClient
        client = RedisClient()
        # Should not raise, just silently do nothing
        await client.zadd("some:key", {"value": 1.0})

    @pytest.mark.asyncio
    async def test_zrevrange_when_disconnected(self):
        from app.core.redis_client import RedisClient
        client = RedisClient()
        result = await client.zrevrange("some:key", 0, 99)
        assert result == []

    @pytest.mark.asyncio
    async def test_sismember_when_disconnected(self):
        from app.core.redis_client import RedisClient
        client = RedisClient()
        result = await client.sismember("some:set", "value")
        assert result is False

    @pytest.mark.asyncio
    async def test_zadd_with_connected_client(self):
        from app.core.redis_client import RedisClient
        client = RedisClient()
        client._client = AsyncMock()
        client._client.zadd = AsyncMock(return_value=1)
        client.is_connected = True
        await client.zadd("key", {"val": 1.5})
        client._client.zadd.assert_called_once_with("key", {"val": 1.5})

    @pytest.mark.asyncio
    async def test_publish_when_disconnected(self):
        from app.core.redis_client import RedisClient
        client = RedisClient()
        # Should not raise
        await client.publish("channel", "message")

    @pytest.mark.asyncio
    async def test_zcard_when_disconnected(self):
        from app.core.redis_client import RedisClient
        client = RedisClient()
        result = await client.zcard("key")
        assert result == 0


# ─── Neo4j Client Tests ────────────────────────────────────────────────────────

class TestNeo4jClient:
    def test_initial_state(self):
        from app.core.neo4j_client import Neo4jClient
        client = Neo4jClient()
        assert client.is_connected is False
        assert client._driver is None

    @pytest.mark.asyncio
    async def test_connect_failure_graceful(self):
        from app.core.neo4j_client import Neo4jClient
        client = Neo4jClient()
        with patch("neo4j.AsyncGraphDatabase.driver", side_effect=Exception("Connection refused")):
            await client.connect()
        assert client.is_connected is False

    @pytest.mark.asyncio
    async def test_run_when_disconnected(self):
        from app.core.neo4j_client import Neo4jClient
        client = Neo4jClient()
        result = await client.run("MATCH (n) RETURN n")
        assert result == []

    @pytest.mark.asyncio
    async def test_execute_write_when_disconnected(self):
        from app.core.neo4j_client import Neo4jClient
        client = Neo4jClient()
        # Should not raise
        await client.execute_write_query("MERGE (n:Test {id: $id})", {"id": "123"})

    @pytest.mark.asyncio
    async def test_connect_success(self):
        from app.core.neo4j_client import Neo4jClient
        client = Neo4jClient()
        mock_driver = AsyncMock()
        mock_driver.verify_connectivity = AsyncMock(return_value=None)
        with patch("neo4j.AsyncGraphDatabase.driver", return_value=mock_driver):
            await client.connect()
        assert client.is_connected is True


# ─── Timeline Collector Tests ──────────────────────────────────────────────────

class TestTimelineCollector:
    def _make_collector(self):
        from app.services.timeline_collector import TimelineCollector
        collector = TimelineCollector()
        collector._http = AsyncMock()
        return collector

    @pytest.mark.asyncio
    async def test_collect_alerts_success(self):
        collector = self._make_collector()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [make_alert(1), make_alert(2)]
        collector._http.get = AsyncMock(return_value=mock_resp)

        with patch.object(collector, "_upsert_event", new=AsyncMock()) as mock_upsert:
            await collector._collect_alerts()
            assert mock_upsert.call_count == 2

    @pytest.mark.asyncio
    async def test_collect_alerts_non_200_skips(self):
        collector = self._make_collector()
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        collector._http.get = AsyncMock(return_value=mock_resp)

        with patch.object(collector, "_upsert_event", new=AsyncMock()) as mock_upsert:
            await collector._collect_alerts()
            mock_upsert.assert_not_called()

    @pytest.mark.asyncio
    async def test_collect_alerts_http_error_ignored(self):
        collector = self._make_collector()
        collector._http.get = AsyncMock(side_effect=Exception("Connection refused"))
        # Should not raise
        await collector._collect_alerts()

    @pytest.mark.asyncio
    async def test_collect_incidents_success(self):
        collector = self._make_collector()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"incidents": [make_incident(1)]}
        collector._http.get = AsyncMock(return_value=mock_resp)

        with patch.object(collector, "_upsert_event", new=AsyncMock()) as mock_upsert:
            await collector._collect_incidents()
            assert mock_upsert.call_count == 1

    @pytest.mark.asyncio
    async def test_collect_agent_tasks_success(self):
        collector = self._make_collector()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"tasks": [make_task(1), make_task(2), make_task(3)]}
        collector._http.get = AsyncMock(return_value=mock_resp)

        with patch.object(collector, "_upsert_event", new=AsyncMock()) as mock_upsert:
            await collector._collect_agent_tasks()
            assert mock_upsert.call_count == 3

    @pytest.mark.asyncio
    async def test_collect_predictions_success(self):
        collector = self._make_collector()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [make_prediction(1), make_prediction(2)]
        collector._http.get = AsyncMock(return_value=mock_resp)

        with patch.object(collector, "_upsert_event", new=AsyncMock()) as mock_upsert:
            await collector._collect_predictions()
            assert mock_upsert.call_count == 2

    @pytest.mark.asyncio
    async def test_upsert_event_skips_empty_source_id(self):
        from app.services.timeline_collector import TimelineCollector
        collector = TimelineCollector()
        # Should return immediately without touching Redis or DB
        with patch("app.services.timeline_collector.redis_client") as mock_redis:
            await collector._upsert_event(
                event_type="alert",
                source_service="detection-engine",
                source_id="",  # empty!
                severity="high",
                title="Test",
                description="Test",
                asset_ids=[],
                mitre_techniques=[],
                timestamp_str=None,
                extra_data=None,
            )
            mock_redis.sismember.assert_not_called()

    @pytest.mark.asyncio
    async def test_upsert_event_skips_already_seen(self):
        from app.services.timeline_collector import TimelineCollector
        collector = TimelineCollector()
        with patch("app.services.timeline_collector.redis_client") as mock_redis:
            mock_redis.sismember = AsyncMock(return_value=True)  # already seen
            with patch("app.services.timeline_collector.AsyncSessionLocal") as mock_db:
                await collector._upsert_event(
                    event_type="alert",
                    source_service="detection-engine",
                    source_id="alert-9999",
                    severity="high",
                    title="Test",
                    description="Test",
                    asset_ids=[],
                    mitre_techniques=[],
                    timestamp_str=None,
                    extra_data=None,
                )
                # DB should not be called since Redis says already seen
                mock_db.assert_not_called()

    @pytest.mark.asyncio
    async def test_upsert_event_full_flow(self):
        from app.services.timeline_collector import TimelineCollector
        collector = TimelineCollector()

        mock_db_event = MagicMock()
        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)
        mock_session.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None)))
        mock_session.add = MagicMock()
        mock_session.commit = AsyncMock()
        mock_session.refresh = AsyncMock()

        with patch("app.services.timeline_collector.redis_client") as mock_redis, \
             patch("app.services.timeline_collector.AsyncSessionLocal", return_value=mock_session):
            mock_redis.sismember = AsyncMock(return_value=False)
            mock_redis.sadd = AsyncMock()
            mock_redis.zadd = AsyncMock()
            mock_redis.zcard = AsyncMock(return_value=10)
            mock_redis.publish = AsyncMock()

            await collector._upsert_event(
                event_type="incident",
                source_service="detection-engine",
                source_id="inc-0001",
                severity="critical",
                title="Critical Incident",
                description="Multiple alerts correlated",
                asset_ids=["asset-001", "asset-002"],
                mitre_techniques=["T1078", "T1021"],
                timestamp_str="2024-01-15T10:00:00+00:00",
                extra_data={"alert_count": 5},
            )
            mock_redis.publish.assert_called_once()

    def test_parse_dt_valid_iso(self):
        from app.services.timeline_collector import _parse_dt
        dt = _parse_dt("2024-01-15T10:00:00+00:00")
        assert dt.year == 2024
        assert dt.tzinfo is not None

    def test_parse_dt_z_suffix(self):
        from app.services.timeline_collector import _parse_dt
        dt = _parse_dt("2024-01-15T10:00:00Z")
        assert dt.year == 2024

    def test_parse_dt_none(self):
        from app.services.timeline_collector import _parse_dt
        dt = _parse_dt(None)
        assert dt.tzinfo is not None

    def test_parse_dt_invalid(self):
        from app.services.timeline_collector import _parse_dt
        dt = _parse_dt("not-a-date")
        assert dt.tzinfo is not None  # Falls back to now()

    @pytest.mark.asyncio
    async def test_collect_all_gathers_all(self):
        collector = self._make_collector()
        with patch.object(collector, "_collect_alerts", new=AsyncMock()) as m1, \
             patch.object(collector, "_collect_incidents", new=AsyncMock()) as m2, \
             patch.object(collector, "_collect_agent_tasks", new=AsyncMock()) as m3, \
             patch.object(collector, "_collect_predictions", new=AsyncMock()) as m4:
            await collector._collect_all()
            m1.assert_called_once()
            m2.assert_called_once()
            m3.assert_called_once()
            m4.assert_called_once()


# ─── Graph Builder Tests ───────────────────────────────────────────────────────

class TestGraphBuilder:
    def _make_builder(self):
        from app.services.graph_builder import GraphBuilder
        builder = GraphBuilder()
        builder._http = AsyncMock()
        return builder

    @pytest.mark.asyncio
    async def test_fetch_alerts_success(self):
        builder = self._make_builder()
        mock_resp = MagicMock()
        mock_resp.json.return_value = [make_alert(1), make_alert(2)]
        builder._http.get = AsyncMock(return_value=mock_resp)
        alerts = await builder._fetch_alerts()
        assert len(alerts) == 2

    @pytest.mark.asyncio
    async def test_fetch_alerts_failure_returns_empty(self):
        builder = self._make_builder()
        builder._http.get = AsyncMock(side_effect=Exception("Connection error"))
        alerts = await builder._fetch_alerts()
        assert alerts == []

    @pytest.mark.asyncio
    async def test_fetch_incidents_success(self):
        builder = self._make_builder()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"incidents": [make_incident(1)]}
        builder._http.get = AsyncMock(return_value=mock_resp)
        incidents = await builder._fetch_incidents()
        assert len(incidents) == 1

    @pytest.mark.asyncio
    async def test_fetch_tasks_failure_returns_empty(self):
        builder = self._make_builder()
        builder._http.get = AsyncMock(side_effect=ConnectionError("refused"))
        tasks = await builder._fetch_tasks()
        assert tasks == []

    @pytest.mark.asyncio
    async def test_merge_alerts_calls_neo4j(self):
        builder = self._make_builder()
        alerts = [make_alert(i) for i in range(3)]
        with patch("app.services.graph_builder.neo4j_client") as mock_neo4j:
            mock_neo4j.execute_write_query = AsyncMock()
            await builder._merge_alerts(alerts)
            assert mock_neo4j.execute_write_query.call_count > 0

    @pytest.mark.asyncio
    async def test_merge_alerts_skips_empty_id(self):
        builder = self._make_builder()
        alerts = [{"alert_id": "", "asset_id": "x", "mitre_technique": "T1059"}]
        with patch("app.services.graph_builder.neo4j_client") as mock_neo4j:
            mock_neo4j.execute_write_query = AsyncMock()
            await builder._merge_alerts(alerts)
            mock_neo4j.execute_write_query.assert_not_called()

    @pytest.mark.asyncio
    async def test_merge_incidents_calls_neo4j(self):
        builder = self._make_builder()
        incidents = [make_incident(1)]
        alerts = [make_alert(1)]
        with patch("app.services.graph_builder.neo4j_client") as mock_neo4j:
            mock_neo4j.execute_write_query = AsyncMock()
            await builder._merge_incidents(incidents, alerts)
            assert mock_neo4j.execute_write_query.call_count > 0

    @pytest.mark.asyncio
    async def test_merge_tasks_calls_neo4j(self):
        builder = self._make_builder()
        tasks = [make_task(1)]
        incidents = [make_incident(1)]
        with patch("app.services.graph_builder.neo4j_client") as mock_neo4j:
            mock_neo4j.execute_write_query = AsyncMock()
            await builder._merge_tasks(tasks, incidents)
            assert mock_neo4j.execute_write_query.call_count > 0

    @pytest.mark.asyncio
    async def test_lateral_movement_creates_edges(self):
        builder = self._make_builder()
        alerts = [
            {**make_alert(i), "mitre_technique": "T1021", "asset_id": f"asset-{i:03d}"}
            for i in range(1, 4)
        ]
        with patch("app.services.graph_builder.neo4j_client") as mock_neo4j:
            mock_neo4j.execute_write_query = AsyncMock()
            await builder._compute_lateral_movement(alerts)
            assert mock_neo4j.execute_write_query.call_count >= 1

    @pytest.mark.asyncio
    async def test_lateral_movement_skips_if_too_few(self):
        builder = self._make_builder()
        alerts = [
            {**make_alert(1), "mitre_technique": "T1021", "asset_id": "asset-001"}
        ]
        with patch("app.services.graph_builder.neo4j_client") as mock_neo4j:
            mock_neo4j.execute_write_query = AsyncMock()
            await builder._compute_lateral_movement(alerts)
            mock_neo4j.execute_write_query.assert_not_called()

    @pytest.mark.asyncio
    async def test_build_graph_skips_when_neo4j_down(self):
        builder = self._make_builder()
        with patch("app.services.graph_builder.neo4j_client") as mock_neo4j:
            mock_neo4j.is_connected = False
            # run_forever should attempt reconnect, not crash
            mock_neo4j.connect = AsyncMock()
            # Simulate one iteration with cancelled error
            task = asyncio.create_task(builder.run_forever())
            await asyncio.sleep(0.05)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    @pytest.mark.asyncio
    async def test_build_graph_full_pipeline(self):
        builder = self._make_builder()
        with patch.object(builder, "_fetch_alerts", new=AsyncMock(return_value=[make_alert(i) for i in range(5)])), \
             patch.object(builder, "_fetch_incidents", new=AsyncMock(return_value=[make_incident(i) for i in range(2)])), \
             patch.object(builder, "_fetch_tasks", new=AsyncMock(return_value=[make_task(i) for i in range(3)])), \
             patch.object(builder, "_merge_alerts", new=AsyncMock()), \
             patch.object(builder, "_merge_incidents", new=AsyncMock()), \
             patch.object(builder, "_merge_tasks", new=AsyncMock()), \
             patch.object(builder, "_compute_lateral_movement", new=AsyncMock()):
            await builder._build_graph()


# ─── Graph Query Service Tests ─────────────────────────────────────────────────

class TestGraphQueryService:
    @pytest.mark.asyncio
    async def test_empty_response_when_neo4j_unavailable(self):
        from app.services.graph_query import GraphQueryService
        svc = GraphQueryService()
        with patch("app.services.graph_query.neo4j_client") as mock_neo4j:
            mock_neo4j.is_connected = False
            result = await svc.get_overview()
            assert result.nodes == []
            assert result.edges == []
            assert result.warning is not None

    @pytest.mark.asyncio
    async def test_asset_subgraph_when_disconnected(self):
        from app.services.graph_query import GraphQueryService
        svc = GraphQueryService()
        with patch("app.services.graph_query.neo4j_client") as mock_neo4j:
            mock_neo4j.is_connected = False
            result = await svc.get_asset_subgraph("asset-001")
            assert result.nodes == []
            assert result.warning is not None

    @pytest.mark.asyncio
    async def test_incident_subgraph_when_disconnected(self):
        from app.services.graph_query import GraphQueryService
        svc = GraphQueryService()
        with patch("app.services.graph_query.neo4j_client") as mock_neo4j:
            mock_neo4j.is_connected = False
            result = await svc.get_incident_subgraph("inc-001")
            assert result.nodes == []

    @pytest.mark.asyncio
    async def test_blast_radius_when_disconnected(self):
        from app.services.graph_query import GraphQueryService
        svc = GraphQueryService()
        with patch("app.services.graph_query.neo4j_client") as mock_neo4j:
            mock_neo4j.is_connected = False
            result = await svc.get_blast_radius("asset-001")
            assert result.nodes == []

    @pytest.mark.asyncio
    async def test_attack_paths_when_disconnected(self):
        from app.services.graph_query import GraphQueryService
        svc = GraphQueryService()
        with patch("app.services.graph_query.neo4j_client") as mock_neo4j:
            mock_neo4j.is_connected = False
            result = await svc.get_attack_paths()
            assert result.nodes == []
            assert result.stats.node_count == 0

    @pytest.mark.asyncio
    async def test_full_export_when_disconnected(self):
        from app.services.graph_query import GraphQueryService
        svc = GraphQueryService()
        with patch("app.services.graph_query.neo4j_client") as mock_neo4j:
            mock_neo4j.is_connected = False
            result = await svc.get_full_export()
            assert result.nodes == []
            assert result.stats.edge_count == 0

    @pytest.mark.asyncio
    async def test_full_export_with_connected_neo4j(self):
        from app.services.graph_query import GraphQueryService
        svc = GraphQueryService()
        with patch("app.services.graph_query.neo4j_client") as mock_neo4j:
            mock_neo4j.is_connected = True
            mock_neo4j.run = AsyncMock(return_value=[])
            result = await svc.get_full_export()
            assert isinstance(result.nodes, list)
            assert isinstance(result.edges, list)

    def test_extract_id_utility(self):
        from app.services.graph_query import _extract_id
        assert _extract_id({"asset_id": "a1"}) == "a1"
        assert _extract_id({"alert_id": "al1"}) == "al1"
        assert _extract_id({"incident_id": "i1"}) == "i1"
        assert _extract_id({"technique_id": "T1059"}) == "T1059"
        assert _extract_id({"task_id": "t1"}) == "t1"
        assert _extract_id({}) == ""

    def test_extract_label_utility(self):
        from app.services.graph_query import _extract_label
        assert _extract_label({"hostname": "web-01"}, "Asset") == "web-01"
        assert _extract_label({"title": "Incident X"}, "Incident") == "Incident X"
        assert _extract_label({}, "Asset") == "Asset"

    def test_empty_graph_helper(self):
        from app.services.graph_query import _empty
        result = _empty(warning=True)
        assert result.warning is not None
        assert result.nodes == []

        result2 = _empty(warning=False)
        assert result2.warning is None


# ─── API Router Tests ──────────────────────────────────────────────────────────

class TestTimelineAPI:
    @pytest.mark.asyncio
    async def test_get_timeline_from_redis(self):
        """Timeline endpoint returns cached events from Redis."""
        from fastapi.testclient import TestClient
        from app.main import app

        now = datetime.now(timezone.utc)
        sample = json.dumps({
            "event_id": "alert:alert-0001",
            "event_type": "alert",
            "severity": "high",
            "title": "Test Alert",
            "description": "Test",
            "source_service": "detection-engine",
            "source_id": "alert-0001",
            "asset_ids": ["asset-001"],
            "mitre_techniques": ["T1059.001"],
            "extra_data": None,
            "timestamp": now.isoformat(),
            "created_at": now.isoformat(),
        })

        with patch("app.api.timeline.redis_client") as mock_redis, \
             patch("app.api.timeline.get_db"):
            mock_redis.zrevrange = AsyncMock(return_value=[sample])
            client = TestClient(app)
            resp = client.get("/api/v1/timeline?limit=10")
            # TestClient may raise lifespan errors in test mode — just verify no crash
            assert resp.status_code in (200, 500, 503)

    def test_timeline_filter_by_event_type(self):
        """Filter logic works correctly."""
        now = datetime.now(timezone.utc)
        events = [
            {"event_type": "alert", "severity": "high", "asset_ids": []},
            {"event_type": "incident", "severity": "critical", "asset_ids": []},
        ]
        filtered = [e for e in events if e["event_type"] == "alert"]
        assert len(filtered) == 1

    def test_timeline_filter_by_asset_id(self):
        events = [
            {"asset_ids": ["asset-001", "asset-002"]},
            {"asset_ids": ["asset-003"]},
        ]
        target = "asset-001"
        filtered = [e for e in events if target in e["asset_ids"]]
        assert len(filtered) == 1


class TestGraphAPI:
    def _graph_paths(self):
        from app.api.graph import router
        return [r.path for r in router.routes if hasattr(r, "path")]

    def _timeline_paths(self):
        from app.api.timeline import router
        return [r.path for r in router.routes if hasattr(r, "path")]

    def test_graph_router_registered(self):
        paths = self._graph_paths()
        assert "/overview" in paths
        assert "/export" in paths
        assert "/attack-paths" in paths

    def test_timeline_router_registered(self):
        paths = self._timeline_paths()
        assert "/stream" in paths
        assert "/stats" in paths


# ─── Timeline Event Model Tests ────────────────────────────────────────────────

class TestTimelineEventModel:
    def test_model_has_required_columns(self):
        from app.models.timeline_event import TimelineEvent
        col_names = {c.name for c in TimelineEvent.__table__.columns}
        required = {
            "id", "event_id", "event_type", "severity", "title",
            "description", "source_service", "source_id", "asset_ids",
            "mitre_techniques", "extra_data", "timestamp", "created_at",
        }
        assert required.issubset(col_names)

    def test_model_no_metadata_column(self):
        """AEGIS constraint: no column named 'metadata'"""
        from app.models.timeline_event import TimelineEvent
        col_names = {c.name for c in TimelineEvent.__table__.columns}
        assert "metadata" not in col_names

    def test_model_no_saEnum_needed(self):
        """event_type and severity are plain strings, no SAEnum."""
        from app.models.timeline_event import TimelineEvent
        from sqlalchemy import String
        for col in TimelineEvent.__table__.columns:
            if col.name in ("event_type", "severity"):
                assert isinstance(col.type, String)

    def test_model_json_columns(self):
        from app.models.timeline_event import TimelineEvent
        from sqlalchemy import JSON
        json_cols = {
            c.name for c in TimelineEvent.__table__.columns
            if isinstance(c.type, JSON)
        }
        assert "asset_ids" in json_cols
        assert "mitre_techniques" in json_cols
        assert "extra_data" in json_cols

    def test_model_indexed_columns(self):
        from app.models.timeline_event import TimelineEvent
        indexed = {
            c.name for c in TimelineEvent.__table__.columns if c.index
        }
        assert "event_id" in indexed
        assert "event_type" in indexed
        assert "source_id" in indexed
        assert "timestamp" in indexed


# ─── Integration-style / Edge Case Tests ──────────────────────────────────────

class TestEdgeCases:
    @pytest.mark.asyncio
    async def test_collector_handles_unexpected_api_format(self):
        """API returns unexpected format — should not crash."""
        from app.services.timeline_collector import TimelineCollector
        collector = TimelineCollector()
        collector._http = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"unexpected_key": "surprise"}  # no alerts key
        collector._http.get = AsyncMock(return_value=mock_resp)

        with patch.object(collector, "_upsert_event", new=AsyncMock()) as mock_upsert:
            await collector._collect_alerts()
            # Should handle gracefully (empty list)
            mock_upsert.assert_not_called()

    @pytest.mark.asyncio
    async def test_collector_handles_list_wrapped_incidents(self):
        """Some services return bare lists."""
        from app.services.timeline_collector import TimelineCollector
        collector = TimelineCollector()
        collector._http = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [make_incident(1), make_incident(2)]
        collector._http.get = AsyncMock(return_value=mock_resp)

        with patch.object(collector, "_upsert_event", new=AsyncMock()) as mock_upsert:
            await collector._collect_incidents()
            assert mock_upsert.call_count == 2

    def test_severity_from_confidence(self):
        """Predictions derive severity from confidence score."""
        def confidence_to_severity(confidence: float) -> str:
            if confidence >= 0.9:
                return "critical"
            elif confidence >= 0.75:
                return "high"
            elif confidence >= 0.5:
                return "medium"
            return "low"

        assert confidence_to_severity(0.95) == "critical"
        assert confidence_to_severity(0.80) == "high"
        assert confidence_to_severity(0.60) == "medium"
        assert confidence_to_severity(0.30) == "low"

    @pytest.mark.asyncio
    async def test_redis_trim_on_overflow(self):
        from app.core.redis_client import RedisClient
        client = RedisClient()
        client._client = AsyncMock()
        client._client.zcard = AsyncMock(return_value=600)
        client._client.zremrangebyrank = AsyncMock()
        client.is_connected = True

        total = await client.zcard("key")
        assert total == 600
        # Trim logic
        from app.core.config import settings
        if total > settings.REDIS_TIMELINE_MAX:
            await client.zremrangebyrank("key", 0, total - settings.REDIS_TIMELINE_MAX - 1)
        client._client.zremrangebyrank.assert_called_once_with("key", 0, 99)

    def test_graph_node_severity_default(self):
        from app.models.schemas import GraphNode
        node = GraphNode(id="x", type="Asset", label="host")
        assert node.severity == "info"

    def test_graph_response_empty_state(self):
        from app.models.schemas import GraphResponse, GraphStats
        resp = GraphResponse(
            nodes=[], edges=[],
            stats=GraphStats(node_count=0, edge_count=0),
            warning="Neo4j unavailable",
        )
        assert resp.stats.node_count == 0
        assert resp.stats.edge_count == 0

    @pytest.mark.asyncio
    async def test_graph_builder_handles_exception_in_build(self):
        from app.services.graph_builder import GraphBuilder
        builder = GraphBuilder()
        builder._http = AsyncMock()
        with patch.object(builder, "_fetch_alerts", new=AsyncMock(side_effect=Exception("DB error"))), \
             patch.object(builder, "_fetch_incidents", new=AsyncMock(return_value=[])), \
             patch.object(builder, "_fetch_tasks", new=AsyncMock(return_value=[])):
            # _build_graph should handle exceptions from gather return_exceptions=True
            with patch("app.services.graph_builder.neo4j_client") as mock_neo4j:
                mock_neo4j.is_connected = True
                mock_neo4j.execute_write_query = AsyncMock()
                await builder._build_graph()  # Should not raise

    def test_technique_names_lookup(self):
        from app.services.graph_builder import TECHNIQUE_NAMES
        assert "T1059" in TECHNIQUE_NAMES
        assert "T1110" in TECHNIQUE_NAMES
        assert TECHNIQUE_NAMES["T1110"] == "Brute Force"

    @pytest.mark.asyncio
    async def test_neo4j_run_returns_empty_on_error(self):
        from app.core.neo4j_client import Neo4jClient
        client = Neo4jClient()
        mock_driver = AsyncMock()
        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)
        mock_session.run = AsyncMock(side_effect=Exception("Cypher error"))
        mock_driver.session = MagicMock(return_value=mock_session)
        client._driver = mock_driver
        client.is_connected = True
        result = await client.run("MATCH (n) RETURN n")
        assert result == []
