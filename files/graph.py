from fastapi import APIRouter

from app.models.schemas import GraphResponse
from app.services.graph_query import GraphQueryService

router = APIRouter()
_svc = GraphQueryService()


@router.get("/overview", response_model=GraphResponse)
async def graph_overview():
    """Node/edge counts and full graph snapshot."""
    return await _svc.get_overview()


@router.get("/asset/{asset_id}", response_model=GraphResponse)
async def graph_asset(asset_id: str):
    """Subgraph centered on an asset (2 hops)."""
    return await _svc.get_asset_subgraph(asset_id)


@router.get("/incident/{incident_id}", response_model=GraphResponse)
async def graph_incident(incident_id: str):
    """Full subgraph for an incident."""
    return await _svc.get_incident_subgraph(incident_id)


@router.get("/blast-radius/{asset_id}", response_model=GraphResponse)
async def blast_radius(asset_id: str):
    """All assets reachable from this asset within 2 hops."""
    return await _svc.get_blast_radius(asset_id)


@router.get("/attack-paths", response_model=GraphResponse)
async def attack_paths():
    """Top 5 most connected attack paths."""
    return await _svc.get_attack_paths()


@router.get("/export", response_model=GraphResponse)
async def export_graph():
    """Full graph as nodes + edges JSON for D3.js rendering."""
    return await _svc.get_full_export()
