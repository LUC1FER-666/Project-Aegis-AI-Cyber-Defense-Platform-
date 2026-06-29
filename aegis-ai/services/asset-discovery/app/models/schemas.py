"""API schemas for the Asset Discovery service."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator
import sys
sys.path.insert(0, "/shared/python")
from aegis_common.models import AssetType


# ---------------------------------------------------------------------------
# Scan request/response
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """
    Body for POST /scans — trigger a new discovery scan.
    target examples:
      "192.168.1.0/24"     → scan entire subnet
      "192.168.1.105"      → scan single host
      "10.0.0.1-10.0.0.50" → scan range
    """
    scan_type: str = Field(default="network", pattern="^(network|host|docker|kubernetes)$")
    target: str = Field(..., description="CIDR, IP, or IP range to scan")
    ports: str | None = Field(None, description="Port list e.g. '22,80,443' or '1-1024'")
    aggressive: bool = Field(False, description="Enable OS detection and version scanning")

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")
        # Basic sanity — real validation happens in the scanner service
        forbidden = ["0.0.0.0/0", "::/0"]
        if v in forbidden:
            raise ValueError("Scanning the entire internet is not allowed")
        return v


class ScanJobRead(BaseModel):
    id: uuid.UUID
    scan_type: str
    target: str
    status: str
    triggered_by: str
    hosts_discovered: int
    hosts_new: int
    hosts_updated: int
    error_message: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Asset schemas
# ---------------------------------------------------------------------------

class PortRead(BaseModel):
    port_number: int
    protocol: str
    state: str
    service_name: str | None
    service_version: str | None

    model_config = {"from_attributes": True}


class SoftwareRead(BaseModel):
    name: str
    version: str | None
    vendor: str | None
    cpe: str | None

    model_config = {"from_attributes": True}


class AssetRead(BaseModel):
    id: uuid.UUID
    hostname: str | None
    ip_address: str
    mac_address: str | None
    asset_type: str
    os_name: str | None
    os_version: str | None
    os_family: str | None
    cloud_provider: str | None
    cloud_region: str | None
    criticality: int
    risk_score: float
    tags: dict[str, Any]
    discovery_method: str
    is_active: bool
    is_managed: bool
    first_seen: datetime
    last_seen: datetime
    open_ports: list[PortRead] = []
    software: list[SoftwareRead] = []

    model_config = {"from_attributes": True}


class AssetSummary(BaseModel):
    """Lightweight version for list views — no ports/software."""
    id: uuid.UUID
    hostname: str | None
    ip_address: str
    asset_type: str
    os_name: str | None
    criticality: int
    risk_score: float
    is_active: bool
    last_seen: datetime

    model_config = {"from_attributes": True}


class AssetUpdate(BaseModel):
    """Manual asset metadata update."""
    hostname: str | None = None
    asset_type: AssetType | None = None
    criticality: int | None = Field(None, ge=1, le=4)
    tags: dict[str, str] | None = None
    is_managed: bool | None = None


class AssetListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[AssetSummary]


class AssetStatsResponse(BaseModel):
    """Dashboard summary counts."""
    total_assets: int
    active_assets: int
    by_type: dict[str, int]
    by_criticality: dict[str, int]
    new_last_24h: int
    unmanaged: int
