"""
Asset management business logic.
Handles deduplication, upsert, risk scoring, and Kafka publishing.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

import sys
sys.path.insert(0, "/shared/python")
from aegis_common.kafka import AegisProducer, Topics
from aegis_common.logging import get_logger

from app.models.db import Asset, AssetPort, AssetSoftware, ScanJob
from app.models.schemas import AssetStatsResponse, AssetUpdate
from app.scanners.network_scanner import DiscoveredHost

logger = get_logger(__name__)


class AssetService:
    def __init__(self, db: AsyncSession, producer: AegisProducer) -> None:
        self.db = db
        self.producer = producer

    # -------------------------------------------------------------------------
    # Asset upsert — the core deduplication logic
    # -------------------------------------------------------------------------

    async def upsert_from_scan(
        self, host: DiscoveredHost, scan_job_id: uuid.UUID
    ) -> tuple[Asset, bool]:
        """
        Insert or update an asset from scan results.
        Deduplication key: ip_address.
        Returns (asset, is_new).
        """
        result = await self.db.execute(
            select(Asset).where(Asset.ip_address == host.ip_address)
        )
        existing = result.scalar_one_or_none()
        is_new = existing is None

        if is_new:
            asset = Asset(
                ip_address=host.ip_address,
                hostname=host.hostname,
                mac_address=host.mac_address,
                os_name=host.os_name,
                os_version=host.os_version,
                os_family=host.os_family,
                asset_type=host.asset_type,
                discovery_method="nmap",
                last_scan_id=scan_job_id,
                extra_data=host.raw_data,
            )
            self.db.add(asset)
            logger.info("asset_created", ip=host.ip_address, hostname=host.hostname)
        else:
            asset = existing
            # Update mutable fields — preserve manually set values
            if host.hostname and not asset.hostname:
                asset.hostname = host.hostname
            if host.mac_address:
                asset.mac_address = host.mac_address
            if host.os_name:
                asset.os_name = host.os_name
            if host.os_version:
                asset.os_version = host.os_version
            if host.os_family:
                asset.os_family = host.os_family
            if host.asset_type != "unknown":
                asset.asset_type = host.asset_type
            asset.last_seen = datetime.now(timezone.utc)
            asset.last_scan_id = scan_job_id
            asset.is_active = True
            logger.debug("asset_updated", ip=host.ip_address)

        await self.db.flush()  # Get the ID without committing

        # Upsert ports
        await self._upsert_ports(asset, host)

        # Calculate risk score
        asset.risk_score = self._calculate_risk_score(asset, host)

        return asset, is_new

    async def _upsert_ports(self, asset: Asset, host: DiscoveredHost) -> None:
        """Replace port records with latest scan results."""
        # Delete old ports for this asset
        from sqlalchemy import delete
        await self.db.execute(
            delete(AssetPort).where(AssetPort.asset_id == asset.id)
        )

        # Insert fresh from scan
        for port in host.ports:
            self.db.add(AssetPort(
                asset_id=asset.id,
                port_number=port.port_number,
                protocol=port.protocol,
                state=port.state,
                service_name=port.service_name,
                service_version=port.service_version,
                service_product=port.service_product,
                banner=port.banner,
            ))

    def _calculate_risk_score(self, asset: Asset, host: DiscoveredHost) -> float:
        """
        Heuristic risk scoring based on open ports and asset type.
        Range: 0.0 - 100.0
        This is the baseline — the AI detection engine refines this in Milestone 3.
        """
        score = 0.0

        # Base score by asset type
        type_scores = {
            "server": 40.0,
            "endpoint": 25.0,
            "network_device": 50.0,
            "database": 60.0,
            "unknown": 30.0,
        }
        score += type_scores.get(asset.asset_type, 30.0)

        # High-risk ports
        high_risk_ports = {
            23: 20,    # Telnet
            21: 15,    # FTP
            3389: 15,  # RDP
            445: 15,   # SMB
            135: 10,   # RPC
            5900: 10,  # VNC
        }
        for port in host.ports:
            score += high_risk_ports.get(port.port_number, 0)

        # More open ports = higher attack surface
        port_count = len(host.ports)
        if port_count > 20:
            score += 15
        elif port_count > 10:
            score += 8
        elif port_count > 5:
            score += 3

        return min(score, 100.0)

    # -------------------------------------------------------------------------
    # Kafka publishing
    # -------------------------------------------------------------------------

    async def publish_asset_discovered(
        self, asset: Asset, is_new: bool, scan_job_id: str
    ) -> None:
        """Publish to aegis.assets.discovered for downstream consumers."""
        await self.producer.publish(
            topic=Topics.ASSETS_DISCOVERED,
            payload={
                "asset_id": str(asset.id),
                "ip_address": asset.ip_address,
                "hostname": asset.hostname,
                "asset_type": asset.asset_type,
                "os_name": asset.os_name,
                "os_family": asset.os_family,
                "open_ports": [p.port_number for p in asset.open_ports],
                "risk_score": asset.risk_score,
                "is_new": is_new,
                "scan_job_id": scan_job_id,
                "discovered_at": datetime.utcnow().isoformat(),
            },
            source_service="asset-discovery",
            key=str(asset.id),
        )

    # -------------------------------------------------------------------------
    # Queries
    # -------------------------------------------------------------------------

    async def get_asset(self, asset_id: uuid.UUID) -> Asset | None:
        result = await self.db.execute(
            select(Asset).where(Asset.id == asset_id)
        )
        return result.scalar_one_or_none()

    async def list_assets(
        self,
        page: int = 1,
        page_size: int = 20,
        asset_type: str | None = None,
        is_active: bool | None = None,
        search: str | None = None,
    ) -> tuple[int, list[Asset]]:
        query = select(Asset)
        count_query = select(func.count(Asset.id))

        if asset_type:
            query = query.where(Asset.asset_type == asset_type)
            count_query = count_query.where(Asset.asset_type == asset_type)
        if is_active is not None:
            query = query.where(Asset.is_active == is_active)
            count_query = count_query.where(Asset.is_active == is_active)
        if search:
            search_filter = (
                Asset.ip_address.ilike(f"%{search}%") |
                Asset.hostname.ilike(f"%{search}%")
            )
            query = query.where(search_filter)
            count_query = count_query.where(search_filter)

        total = (await self.db.execute(count_query)).scalar_one()
        assets = (
            await self.db.execute(
                query.order_by(Asset.last_seen.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).scalars().all()

        return total, list(assets)

    async def get_stats(self) -> AssetStatsResponse:
        """Dashboard summary statistics."""
        yesterday = datetime.now(timezone.utc) - timedelta(hours=24)

        total = (await self.db.execute(select(func.count(Asset.id)))).scalar_one()
        active = (await self.db.execute(
            select(func.count(Asset.id)).where(Asset.is_active == True)  # noqa: E712
        )).scalar_one()
        new_24h = (await self.db.execute(
            select(func.count(Asset.id)).where(Asset.first_seen >= yesterday)
        )).scalar_one()
        unmanaged = (await self.db.execute(
            select(func.count(Asset.id)).where(Asset.is_managed == False)  # noqa: E712
        )).scalar_one()

        # Group by type
        type_result = await self.db.execute(
            select(Asset.asset_type, func.count(Asset.id)).group_by(Asset.asset_type)
        )
        by_type = {row[0]: row[1] for row in type_result}

        # Group by criticality
        crit_map = {1: "critical", 2: "high", 3: "medium", 4: "low"}
        crit_result = await self.db.execute(
            select(Asset.criticality, func.count(Asset.id)).group_by(Asset.criticality)
        )
        by_criticality = {crit_map.get(row[0], str(row[0])): row[1] for row in crit_result}

        return AssetStatsResponse(
            total_assets=total,
            active_assets=active,
            by_type=by_type,
            by_criticality=by_criticality,
            new_last_24h=new_24h,
            unmanaged=unmanaged,
        )

    async def update_asset(
        self, asset_id: uuid.UUID, update_data: AssetUpdate
    ) -> Asset | None:
        asset = await self.get_asset(asset_id)
        if not asset:
            return None

        update_dict = update_data.model_dump(exclude_none=True)
        if "asset_type" in update_dict:
            update_dict["asset_type"] = update_dict["asset_type"].value

        for key, value in update_dict.items():
            setattr(asset, key, value)

        return asset
