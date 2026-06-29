"""
Asset Discovery API routes.
POST /scans — trigger scan
GET  /scans — list scan jobs
GET  /scans/{id} — scan job status
GET  /assets — list all assets
GET  /assets/stats — dashboard counts
GET  /assets/{id} — asset detail
PATCH /assets/{id} — update metadata
"""
from __future__ import annotations

import asyncio
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import sys
sys.path.insert(0, "/shared/python")
from aegis_common.logging import get_logger

from app.database import DBSession, get_session_factory
from app.dependencies import CurrentUser, RequireSOCAnalyst
from app.models.db import Asset, AssetPort, AssetSoftware, ScanJob
from app.models.schemas import (
    AssetListResponse,
    AssetRead,
    AssetStatsResponse,
    AssetUpdate,
    ScanJobRead,
    ScanRequest,
)
from app.services.asset_service import AssetService
from app.services.scan_service import ScanService
from app.scanners.network_scanner import NetworkScanner
from app.config import get_settings

logger = get_logger(__name__)
settings = get_settings()

router = APIRouter(tags=["Assets & Discovery"])


def get_scanner() -> NetworkScanner:
    return NetworkScanner(
        default_ports=settings.default_scan_ports,
        excluded_ranges=settings.excluded_ranges.split(","),
        timeout=settings.scan_timeout,
    )


# ---------------------------------------------------------------------------
# Scan endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/scans",
    response_model=ScanJobRead,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger a new asset discovery scan",
)
async def trigger_scan(
    body: ScanRequest,
    request: Request,
    current_user: CurrentUser,
    _: Annotated[None, RequireSOCAnalyst],
    db: DBSession,
    session_factory=Depends(get_session_factory),
) -> ScanJobRead:
    """
    Trigger an async network scan. Returns immediately with a job ID.
    Poll GET /scans/{id} to check progress.

    The scan runs in the background — the API response arrives before
    the scan completes. This is intentional for large network ranges.
    """
    from app.kafka_client import get_producer

    producer = await get_producer()
    scanner = get_scanner()
    scan_svc = ScanService(session_factory, producer, scanner)

    job = await scan_svc.create_scan_job(body, str(current_user.id), db)
    await db.commit()

    # Fire and forget — scan runs in background
    asyncio.create_task(scan_svc.run_scan_background(job.id))

    logger.info(
        "scan_triggered",
        job_id=str(job.id),
        target=body.target,
        by=str(current_user.id),
    )

    return ScanJobRead.model_validate(job)


@router.get("/scans", response_model=list[ScanJobRead], summary="List scan jobs")
async def list_scans(
    current_user: CurrentUser,
    db: DBSession,
    limit: int = Query(default=20, ge=1, le=100),
) -> list[ScanJobRead]:
    result = await db.execute(
        select(ScanJob).order_by(ScanJob.created_at.desc()).limit(limit)
    )
    jobs = result.scalars().all()
    return [ScanJobRead.model_validate(j) for j in jobs]


@router.get("/scans/{job_id}", response_model=ScanJobRead, summary="Get scan job status")
async def get_scan(
    job_id: uuid.UUID,
    current_user: CurrentUser,
    db: DBSession,
) -> ScanJobRead:
    result = await db.execute(select(ScanJob).where(ScanJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return ScanJobRead.model_validate(job)


# ---------------------------------------------------------------------------
# Asset endpoints
# ---------------------------------------------------------------------------

@router.get("/assets/stats", response_model=AssetStatsResponse, summary="Asset inventory statistics")
async def get_asset_stats(
    current_user: CurrentUser,
    db: DBSession,
) -> AssetStatsResponse:
    """Summary counts for the SOC and executive dashboards."""
    from app.kafka_client import get_producer
    producer = await get_producer()
    svc = AssetService(db, producer)
    return await svc.get_stats()


@router.get("/assets", response_model=AssetListResponse, summary="List all assets")
async def list_assets(
    current_user: CurrentUser,
    db: DBSession,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    asset_type: str | None = None,
    is_active: bool | None = None,
    search: str | None = Query(None, description="Search by IP or hostname"),
) -> AssetListResponse:
    from app.kafka_client import get_producer
    from app.models.schemas import AssetSummary
    producer = await get_producer()
    svc = AssetService(db, producer)
    total, assets = await svc.list_assets(page, page_size, asset_type, is_active, search)
    return AssetListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[AssetSummary.model_validate(a) for a in assets],
    )


@router.get("/assets/{asset_id}", response_model=AssetRead, summary="Get full asset details")
async def get_asset(
    asset_id: uuid.UUID,
    current_user: CurrentUser,
    db: DBSession,
) -> AssetRead:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return AssetRead.model_validate(asset)


@router.patch("/assets/{asset_id}", response_model=AssetRead, summary="Update asset metadata")
async def update_asset(
    asset_id: uuid.UUID,
    body: AssetUpdate,
    current_user: CurrentUser,
    _: Annotated[None, RequireSOCAnalyst],
    db: DBSession,
) -> AssetRead:
    """Update criticality, tags, asset type, or managed status."""
    from app.kafka_client import get_producer
    producer = await get_producer()
    svc = AssetService(db, producer)
    asset = await svc.update_asset(asset_id, body)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return AssetRead.model_validate(asset)
