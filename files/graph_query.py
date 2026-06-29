"""
GraphQueryService — runs Cypher queries and converts results to D3.js-compatible format.
All methods return GraphResponse, with graceful empty state when Neo4j is unavailable.
"""
import logging

from app.core.neo4j_client import neo4j_client
from app.models.schemas import GraphResponse, GraphNode, GraphEdge, GraphStats

logger = logging.getLogger(__name__)

_WARNING = "Neo4j is unavailable — graph data is empty. Check your Neo4j connection."


def _empty(warning: bool = False) -> GraphResponse:
    return GraphResponse(
        nodes=[],
        edges=[],
        stats=GraphStats(node_count=0, edge_count=0),
        warning=_WARNING if warning else None,
    )


def _severity_from_props(props: dict) -> str:
    return props.get("severity", "info")


def _records_to_graph(records: list[dict]) -> GraphResponse:
    """Convert Neo4j records with 'nodes' and 'edges' keys to GraphResponse."""
    nodes: dict[str, GraphNode] = {}
    edges: list[GraphEdge] = []

    for rec in records:
        node_data = rec.get("node", rec.get("n", rec.get("asset", rec.get("a", None))))
        if node_data and hasattr(node_data, "_properties"):
            props = dict(node_data._properties)
            labels = list(node_data.labels)
            node_type = labels[0] if labels else "Unknown"
            node_id = (
                props.get("asset_id")
                or props.get("alert_id")
                or props.get("incident_id")
                or props.get("technique_id")
                or props.get("task_id")
                or str(node_data.id)
            )
            label = (
                props.get("hostname")
                or props.get("rule_id")
                or props.get("title")
                or props.get("name")
                or props.get("playbook")
                or node_id
            )
            if node_id and node_id not in nodes:
                nodes[node_id] = GraphNode(
                    id=node_id,
                    type=node_type,
                    label=str(label),
                    severity=_severity_from_props(props),
                    properties=props,
                )

    return GraphResponse(
        nodes=list(nodes.values()),
        edges=edges,
        stats=GraphStats(node_count=len(nodes), edge_count=len(edges)),
    )


async def _query_subgraph(cypher: str, params: dict = None) -> GraphResponse:
    """Run a Cypher query that returns nodes and relationships."""
    if not neo4j_client.is_connected:
        return _empty(warning=True)
    try:
        records = await neo4j_client.run(cypher, params or {})
        return _build_graph_from_path_records(records)
    except Exception as e:
        logger.warning(f"Graph query error: {e}")
        return _empty(warning=True)


def _build_graph_from_path_records(records: list[dict]) -> GraphResponse:
    """Parse records that may contain 'nodes' list and 'rels' list."""
    node_map: dict[str, GraphNode] = {}
    edge_list: list[GraphEdge] = []
    seen_edges: set[str] = set()

    for rec in records:
        # Handle structured returns: nodes list and rels list
        for key in ["nodes", "n", "asset", "a", "alert", "incident", "task", "tech"]:
            val = rec.get(key)
            if val is None:
                continue
            items = val if isinstance(val, list) else [val]
            for item in items:
                if item is None:
                    continue
                try:
                    props = dict(item)
                    labels = list(item.labels) if hasattr(item, "labels") else []
                    node_type = labels[0] if labels else "Unknown"
                    node_id = _extract_id(props)
                    if node_id and node_id not in node_map:
                        node_map[node_id] = GraphNode(
                            id=node_id,
                            type=node_type,
                            label=_extract_label(props, node_type),
                            severity=props.get("severity", "info"),
                            properties=props,
                        )
                except Exception:
                    pass

        # Handle relationships
        for key in ["rels", "r", "rel", "relationships"]:
            val = rec.get(key)
            if val is None:
                continue
            rels = val if isinstance(val, list) else [val]
            for rel in rels:
                if rel is None:
                    continue
                try:
                    src = str(rel.start_node.id)
                    dst = str(rel.end_node.id)
                    rel_type = rel.type
                    edge_key = f"{src}-{rel_type}-{dst}"
                    if edge_key not in seen_edges:
                        seen_edges.add(edge_key)
                        # Use property IDs when available
                        src_id = _extract_id(dict(rel.start_node)) or src
                        dst_id = _extract_id(dict(rel.end_node)) or dst
                        edge_list.append(GraphEdge(source=src_id, target=dst_id, type=rel_type))
                except Exception:
                    pass

    return GraphResponse(
        nodes=list(node_map.values()),
        edges=edge_list,
        stats=GraphStats(node_count=len(node_map), edge_count=len(edge_list)),
    )


def _extract_id(props: dict) -> str:
    for key in ("asset_id", "alert_id", "incident_id", "technique_id", "task_id"):
        if props.get(key):
            return str(props[key])
    return ""


def _extract_label(props: dict, node_type: str) -> str:
    for key in ("hostname", "rule_id", "title", "name", "playbook", "technique_id"):
        if props.get(key):
            return str(props[key])
    return node_type


class GraphQueryService:
    async def get_overview(self) -> GraphResponse:
        if not neo4j_client.is_connected:
            return _empty(warning=True)
        try:
            count_records = await neo4j_client.run("MATCH (n) RETURN count(n) as node_count")
            edge_records = await neo4j_client.run("MATCH ()-[r]->() RETURN count(r) as edge_count")
            node_count = count_records[0]["node_count"] if count_records else 0
            edge_count = edge_records[0]["edge_count"] if edge_records else 0
            # Return full export for overview
            return await self.get_full_export()
        except Exception as e:
            logger.warning(f"Overview error: {e}")
            return _empty(warning=True)

    async def get_asset_subgraph(self, asset_id: str) -> GraphResponse:
        cypher = """
        MATCH (asset:Asset {asset_id: $asset_id})
        OPTIONAL MATCH (asset)<-[r1:TRIGGERED_ON]-(alert:Alert)
        OPTIONAL MATCH (alert)-[r2:USES]->(tech:Technique)
        OPTIONAL MATCH (inc:Incident)-[r3:AFFECTS]->(asset)
        OPTIONAL MATCH (asset)-[r4:LATERAL_MOVE_TO]-(other:Asset)
        RETURN
          collect(DISTINCT asset) + collect(DISTINCT alert) +
          collect(DISTINCT tech) + collect(DISTINCT inc) +
          collect(DISTINCT other) AS nodes,
          collect(DISTINCT r1) + collect(DISTINCT r2) +
          collect(DISTINCT r3) + collect(DISTINCT r4) AS rels
        """
        return await _query_subgraph(cypher, {"asset_id": asset_id})

    async def get_incident_subgraph(self, incident_id: str) -> GraphResponse:
        cypher = """
        MATCH (inc:Incident {incident_id: $incident_id})
        OPTIONAL MATCH (inc)-[r1:CONTAINS]->(alert:Alert)
        OPTIONAL MATCH (alert)-[r2:TRIGGERED_ON]->(asset:Asset)
        OPTIONAL MATCH (alert)-[r3:USES]->(tech:Technique)
        OPTIONAL MATCH (inc)-[r4:AFFECTS]->(iasset:Asset)
        OPTIONAL MATCH (task:AgentTask)-[r5:RESPONDS_TO]->(inc)
        RETURN
          collect(DISTINCT inc) + collect(DISTINCT alert) +
          collect(DISTINCT asset) + collect(DISTINCT tech) +
          collect(DISTINCT iasset) + collect(DISTINCT task) AS nodes,
          collect(DISTINCT r1) + collect(DISTINCT r2) +
          collect(DISTINCT r3) + collect(DISTINCT r4) +
          collect(DISTINCT r5) AS rels
        """
        return await _query_subgraph(cypher, {"incident_id": incident_id})

    async def get_blast_radius(self, asset_id: str) -> GraphResponse:
        cypher = """
        MATCH (start:Asset {asset_id: $asset_id})
        MATCH path = (start)-[*1..2]-(reachable)
        RETURN collect(DISTINCT reachable) AS nodes, [] AS rels
        """
        return await _query_subgraph(cypher, {"asset_id": asset_id})

    async def get_attack_paths(self) -> GraphResponse:
        """Top 5 most connected nodes and their neighbors."""
        if not neo4j_client.is_connected:
            return _empty(warning=True)
        try:
            # Find most connected assets
            records = await neo4j_client.run(
                """
                MATCH (n)
                WITH n, size([(n)-[]-() | 1]) AS degree
                ORDER BY degree DESC
                LIMIT 5
                RETURN collect(DISTINCT n) AS nodes
                """
            )
            nodes = []
            if records and records[0].get("nodes"):
                for node in records[0]["nodes"]:
                    props = dict(node)
                    labels = list(node.labels) if hasattr(node, "labels") else []
                    node_type = labels[0] if labels else "Unknown"
                    node_id = _extract_id(props)
                    if node_id:
                        nodes.append(GraphNode(
                            id=node_id,
                            type=node_type,
                            label=_extract_label(props, node_type),
                            severity=props.get("severity", "info"),
                            properties=props,
                        ))
            return GraphResponse(
                nodes=nodes,
                edges=[],
                stats=GraphStats(node_count=len(nodes), edge_count=0),
            )
        except Exception as e:
            logger.warning(f"Attack paths error: {e}")
            return _empty(warning=True)

    async def get_full_export(self) -> GraphResponse:
        """Export the entire graph for D3.js rendering."""
        if not neo4j_client.is_connected:
            return _empty(warning=True)
        try:
            node_records = await neo4j_client.run(
                "MATCH (n) RETURN n, labels(n) AS labels LIMIT 500"
            )
            rel_records = await neo4j_client.run(
                "MATCH (a)-[r]->(b) RETURN a, r, b, type(r) AS rel_type LIMIT 1000"
            )

            node_map: dict[str, GraphNode] = {}
            for rec in node_records:
                node = rec.get("n")
                if node is None:
                    continue
                props = dict(node)
                labels_list = rec.get("labels", list(node.labels) if hasattr(node, "labels") else [])
                node_type = labels_list[0] if labels_list else "Unknown"
                node_id = _extract_id(props)
                if not node_id:
                    continue
                node_map[node_id] = GraphNode(
                    id=node_id,
                    type=node_type,
                    label=_extract_label(props, node_type),
                    severity=props.get("severity", "info"),
                    properties=props,
                )

            edges = []
            seen: set[str] = set()
            for rec in rel_records:
                a_node = rec.get("a")
                b_node = rec.get("b")
                rel_type = rec.get("rel_type", "RELATED")
                if a_node is None or b_node is None:
                    continue
                src_id = _extract_id(dict(a_node))
                dst_id = _extract_id(dict(b_node))
                if not src_id or not dst_id:
                    continue
                key = f"{src_id}-{rel_type}-{dst_id}"
                if key not in seen:
                    seen.add(key)
                    edges.append(GraphEdge(source=src_id, target=dst_id, type=rel_type))

            return GraphResponse(
                nodes=list(node_map.values()),
                edges=edges,
                stats=GraphStats(node_count=len(node_map), edge_count=len(edges)),
            )
        except Exception as e:
            logger.warning(f"Full export error: {e}")
            return _empty(warning=True)
