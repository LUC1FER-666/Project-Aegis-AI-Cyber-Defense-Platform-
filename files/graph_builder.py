"""
GraphBuilder — updates Neo4j with the latest alerts, incidents, tasks, and assets every 30 seconds.
Uses MERGE to avoid duplicates.
"""
import asyncio
import logging

import httpx

from app.core.config import settings
from app.core.neo4j_client import neo4j_client

logger = logging.getLogger(__name__)

# Known MITRE technique names (abbreviated)
TECHNIQUE_NAMES = {
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1053": "Scheduled Task/Job",
    "T1053.005": "Scheduled Task",
    "T1110": "Brute Force",
    "T1071": "Application Layer Protocol",
    "T1071.004": "DNS",
    "T1571": "Non-Standard Port",
    "T1021": "Remote Services",
    "T1078": "Valid Accounts",
    "T1003": "OS Credential Dumping",
    "T1055": "Process Injection",
}


class GraphBuilder:
    def __init__(self):
        self._http = httpx.AsyncClient(timeout=5.0)

    async def run_forever(self):
        logger.info("GraphBuilder started")
        while True:
            try:
                if neo4j_client.is_connected:
                    await self._build_graph()
                else:
                    await neo4j_client.connect()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"GraphBuilder error: {e}")
            await asyncio.sleep(settings.GRAPH_BUILD_INTERVAL)
        await self._http.aclose()

    async def _build_graph(self):
        alerts, incidents, tasks = await asyncio.gather(
            self._fetch_alerts(),
            self._fetch_incidents(),
            self._fetch_tasks(),
            return_exceptions=True,
        )
        if isinstance(alerts, Exception):
            alerts = []
        if isinstance(incidents, Exception):
            incidents = []
        if isinstance(tasks, Exception):
            tasks = []

        await self._merge_alerts(alerts)
        await self._merge_incidents(incidents, alerts)
        await self._merge_tasks(tasks, incidents)
        await self._compute_lateral_movement(alerts)
        logger.info(
            f"Graph updated: {len(alerts)} alerts, {len(incidents)} incidents, {len(tasks)} tasks"
        )

    # ─── Fetch helpers ────────────────────────────────────────────────────────

    async def _fetch_alerts(self) -> list[dict]:
        try:
            resp = await self._http.get(
                f"{settings.DETECTION_ENGINE_URL}/api/v1/alerts?limit=100"
            )
            data = resp.json()
            return data if isinstance(data, list) else data.get("alerts", data.get("items", []))
        except Exception:
            return []

    async def _fetch_incidents(self) -> list[dict]:
        try:
            resp = await self._http.get(
                f"{settings.DETECTION_ENGINE_URL}/api/v1/incidents?limit=50"
            )
            data = resp.json()
            return data if isinstance(data, list) else data.get("incidents", data.get("items", []))
        except Exception:
            return []

    async def _fetch_tasks(self) -> list[dict]:
        try:
            resp = await self._http.get(
                f"{settings.AGENT_ORCHESTRATOR_URL}/api/v1/tasks?page_size=50"
            )
            data = resp.json()
            return data if isinstance(data, list) else data.get("tasks", data.get("items", []))
        except Exception:
            return []

    # ─── Neo4j merge operations ───────────────────────────────────────────────

    async def _merge_alerts(self, alerts: list[dict]):
        for alert in alerts:
            alert_id = alert.get("alert_id", "")
            asset_id = alert.get("asset_id", "")
            technique = alert.get("mitre_technique", "")
            if not alert_id:
                continue

            # Merge Alert node
            await neo4j_client.execute_write_query(
                """
                MERGE (a:Alert {alert_id: $alert_id})
                SET a.rule_id = $rule_id,
                    a.severity = $severity,
                    a.mitre_technique = $technique,
                    a.confidence_score = $confidence,
                    a.created_at = $created_at
                """,
                {
                    "alert_id": alert_id,
                    "rule_id": alert.get("rule_id", "unknown"),
                    "severity": alert.get("severity", "info"),
                    "technique": technique,
                    "confidence": float(alert.get("confidence_score", 0)),
                    "created_at": str(alert.get("created_at", "")),
                },
            )

            # Merge Asset node + relationship
            if asset_id:
                await neo4j_client.execute_write_query(
                    """
                    MERGE (asset:Asset {asset_id: $asset_id})
                    SET asset.last_seen = $last_seen
                    WITH asset
                    MATCH (a:Alert {alert_id: $alert_id})
                    MERGE (a)-[:TRIGGERED_ON]->(asset)
                    """,
                    {
                        "asset_id": asset_id,
                        "alert_id": alert_id,
                        "last_seen": str(alert.get("created_at", "")),
                    },
                )

            # Merge Technique node + relationship
            if technique:
                tech_name = TECHNIQUE_NAMES.get(technique, technique)
                await neo4j_client.execute_write_query(
                    """
                    MERGE (t:Technique {technique_id: $technique_id})
                    SET t.name = $name
                    WITH t
                    MATCH (a:Alert {alert_id: $alert_id})
                    MERGE (a)-[:USES]->(t)
                    """,
                    {
                        "technique_id": technique,
                        "name": tech_name,
                        "alert_id": alert_id,
                    },
                )

    async def _merge_incidents(self, incidents: list[dict], alerts: list[dict]):
        # Build lookup of alert -> incident from incident data
        alert_lookup: dict[str, str] = {}
        for inc in incidents:
            incident_id = inc.get("incident_id", "")
            if not incident_id:
                continue

            # Merge Incident node
            await neo4j_client.execute_write_query(
                """
                MERGE (i:Incident {incident_id: $incident_id})
                SET i.title = $title,
                    i.severity = $severity,
                    i.status = $status,
                    i.created_at = $created_at
                """,
                {
                    "incident_id": incident_id,
                    "title": inc.get("title", "Unknown"),
                    "severity": inc.get("severity", "info"),
                    "status": inc.get("status", "open"),
                    "created_at": str(inc.get("created_at", "")),
                },
            )

            # Connect incident to affected assets
            for asset_id in inc.get("affected_assets", []):
                await neo4j_client.execute_write_query(
                    """
                    MERGE (asset:Asset {asset_id: $asset_id})
                    WITH asset
                    MATCH (i:Incident {incident_id: $incident_id})
                    MERGE (i)-[:AFFECTS]->(asset)
                    """,
                    {"asset_id": asset_id, "incident_id": incident_id},
                )

        # Connect alerts to incidents via correlation_key matching
        inc_by_key = {inc.get("correlation_key", ""): inc.get("incident_id", "") for inc in incidents}
        for alert in alerts:
            # Try to find an incident that might contain this alert
            # Use asset_id as heuristic correlation
            asset_id = alert.get("asset_id", "")
            for inc in incidents:
                if asset_id and asset_id in inc.get("affected_assets", []):
                    await neo4j_client.execute_write_query(
                        """
                        MATCH (i:Incident {incident_id: $incident_id})
                        MATCH (a:Alert {alert_id: $alert_id})
                        MERGE (i)-[:CONTAINS]->(a)
                        """,
                        {
                            "incident_id": inc["incident_id"],
                            "alert_id": alert["alert_id"],
                        },
                    )
                    break

    async def _merge_tasks(self, tasks: list[dict], incidents: list[dict]):
        for task in tasks:
            task_id = task.get("id", "")
            incident_id = task.get("incident_id", "")
            if not task_id:
                continue

            # Merge AgentTask node
            await neo4j_client.execute_write_query(
                """
                MERGE (t:AgentTask {task_id: $task_id})
                SET t.playbook = $playbook,
                    t.status = $status,
                    t.created_at = $created_at
                """,
                {
                    "task_id": task_id,
                    "playbook": task.get("selected_playbook", "unknown"),
                    "status": task.get("status", "unknown"),
                    "created_at": str(task.get("created_at", "")),
                },
            )

            # Connect to incident
            if incident_id:
                await neo4j_client.execute_write_query(
                    """
                    MERGE (i:Incident {incident_id: $incident_id})
                    WITH i
                    MATCH (t:AgentTask {task_id: $task_id})
                    MERGE (t)-[:RESPONDS_TO]->(i)
                    """,
                    {"incident_id": incident_id, "task_id": task_id},
                )

    async def _compute_lateral_movement(self, alerts: list[dict]):
        """Create LATERAL_MOVE_TO edges between assets when lateral movement techniques detected."""
        lateral_techniques = {"T1021", "T1021.001", "T1021.002", "T1021.006", "T1210", "T1570"}
        lateral_alerts = [
            a for a in alerts
            if a.get("mitre_technique", "") in lateral_techniques
        ]
        if len(lateral_alerts) < 2:
            return

        # Group by timestamp proximity — pair assets that triggered lateral movement
        asset_ids = list({a["asset_id"] for a in lateral_alerts if a.get("asset_id")})
        for i in range(len(asset_ids) - 1):
            await neo4j_client.execute_write_query(
                """
                MATCH (a:Asset {asset_id: $src})
                MATCH (b:Asset {asset_id: $dst})
                MERGE (a)-[:LATERAL_MOVE_TO]->(b)
                """,
                {"src": asset_ids[i], "dst": asset_ids[i + 1]},
            )
