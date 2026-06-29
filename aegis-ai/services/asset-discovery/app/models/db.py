"""
Database models for the Asset Discovery service.
Assets, scan jobs, open ports, software inventory.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean, DateTime, Float, Integer,
    String, Text, Index, SmallInteger,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID, INET
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    pass


class Asset(Base):
    """
    Central asset record. One row per unique device.
    Deduplication key: ip_address (within a scan scope).
    """
    __tablename__ = "assets"
    __table_args__ = (
        Index("idx_assets_ip", "ip_address"),
        Index("idx_assets_type", "asset_type"),
        Index("idx_assets_active", "is_active"),
        Index("idx_assets_criticality", "criticality"),
        {"schema": "assets"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    hostname: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)  # IPv4 or IPv6
    mac_address: Mapped[str | None] = mapped_column(String(17))
    asset_type: Mapped[str] = mapped_column(String(50), default="unknown")
    os_name: Mapped[str | None] = mapped_column(String(100))
    os_version: Mapped[str | None] = mapped_column(String(50))
    os_family: Mapped[str | None] = mapped_column(String(50))  # windows, linux, macos
    cloud_provider: Mapped[str | None] = mapped_column(String(50))
    cloud_region: Mapped[str | None] = mapped_column(String(50))
    cloud_instance_id: Mapped[str | None] = mapped_column(String(100))

    # Risk and classification
    criticality: Mapped[int] = mapped_column(SmallInteger, default=3)  # 1=critical, 4=low
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    tags: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Discovery metadata
    discovery_method: Mapped[str] = mapped_column(String(50), default="nmap")
    last_scan_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_managed: Mapped[bool] = mapped_column(Boolean, default=False)  # Known/approved asset
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Raw scan data for reference
    extra_data: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Relationships
    open_ports: Mapped[list[AssetPort]] = relationship(
        "AssetPort", back_populates="asset", cascade="all, delete-orphan"
    )
    software: Mapped[list[AssetSoftware]] = relationship(
        "AssetSoftware", back_populates="asset", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Asset {self.ip_address} ({self.hostname or 'unknown'})>"


class AssetPort(Base):
    """Open ports discovered on an asset."""
    __tablename__ = "asset_ports"
    __table_args__ = (
        Index("idx_ports_asset_id", "asset_id"),
        Index("idx_ports_port_number", "port_number"),
        {"schema": "assets"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False
    )
    port_number: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), default="tcp")
    state: Mapped[str] = mapped_column(String(20), default="open")
    service_name: Mapped[str | None] = mapped_column(String(100))
    service_version: Mapped[str | None] = mapped_column(String(255))
    service_product: Mapped[str | None] = mapped_column(String(255))
    banner: Mapped[str | None] = mapped_column(Text)
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    asset: Mapped[Asset] = relationship("Asset", back_populates="open_ports")


class AssetSoftware(Base):
    """Software/packages installed on an asset (from agent or scan)."""
    __tablename__ = "asset_software"
    __table_args__ = (
        Index("idx_software_asset_id", "asset_id"),
        Index("idx_software_name", "name"),
        {"schema": "assets"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str | None] = mapped_column(String(100))
    vendor: Mapped[str | None] = mapped_column(String(255))
    install_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cpe: Mapped[str | None] = mapped_column(String(500))  # CPE identifier for CVE matching

    asset: Mapped[Asset] = relationship("Asset", back_populates="software")


class ScanJob(Base):
    """
    Tracks every scan request — who triggered it, scope, status, results.
    Essential for audit trail and understanding what was scanned when.
    """
    __tablename__ = "scan_jobs"
    __table_args__ = (
        Index("idx_scanjob_status", "status"),
        Index("idx_scanjob_created", "created_at"),
        {"schema": "assets"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_type: Mapped[str] = mapped_column(String(50))  # network, host, cloud, docker, k8s
    target: Mapped[str] = mapped_column(String(500))    # CIDR, hostname, "aws:us-east-1", etc.
    status: Mapped[str] = mapped_column(String(30), default="pending")
    # pending → running → completed | failed | cancelled

    triggered_by: Mapped[str] = mapped_column(String(255))  # user ID or "scheduler"
    scan_options: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Results summary
    hosts_discovered: Mapped[int] = mapped_column(Integer, default=0)
    hosts_new: Mapped[int] = mapped_column(Integer, default=0)
    hosts_updated: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
