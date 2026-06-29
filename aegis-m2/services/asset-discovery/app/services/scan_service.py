"""
Scan job orchestration.
Creates scan jobs, runs the scanner, updates job status, and triggers
asset upserts. Designed to run as a background task.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import sys
sys.path.insert(0, "/shared/python")
from aegis_common.kafka import AegisProducer
from aegis_common.logging import get_logger

from app.models.db import ScanJob
from app.models.schemas import ScanRequest
from app.scanners.network_scanner import NetworkScanner
from app.services.asset_service import AssetService

logger = get_logger(__name__)

# Track running scans to enforce concurrency limit
_running_scans: set[uuid.UUID] = set()
_MAX_CONCURRENT = 3


class ScanService:
    def __init__(
        self,
        session_factory: async_sessionmaker,
        producer: AegisProducer,
        scanner: NetworkScanner,
    ) -> None:
        self.session_factory = session_factory
        self.producer = producer
        self.scanner = scanner

    async def create_scan_job(
        self, request: ScanRequest, triggered_by: str, db: AsyncSession
    ) -> ScanJob:
        """Create a scan job record and return it. Does not start the scan."""
        job = ScanJob(
            scan_type=request.scan_type,
            target=request.target,
            status="pending",
            triggered_by=triggered_by,
            scan_options={
                "ports": request.ports,
                "aggressive": request.aggressive,
            },
        )
        db.add(job)
        await db.flush()
        logger.info("scan_job_created", job_id=str(job.id), target=request.target)
        return job

    async def run_scan_background(self, job_id: uuid.UUID) -> None:
        """
        Execute a scan job in the background.
        Called via asyncio.create_task — runs independently of the request.
        Uses its own DB session since the request session will have closed.
        """
        if len(_running_scans) >= _MAX_CONCURRENT:
            logger.warning("scan_concurrency_limit_reached", job_id=str(job_id))
            await self._update_job_status(job_id, "failed", "Concurrency limit reached")
            return

        _running_scans.add(job_id)

        try:
            async with self.session_factory() as db:
                # Load job
                result = await db.execute(select(ScanJob).where(ScanJob.id == job_id))
                job = result.scalar_one_or_none()
                if not job:
                    return

                # Mark as running
                job.status = "running"
                job.started_at = datetime.now(timezone.utc)
                await db.commit()

                # Run the scan
                logger.info("scan_running", job_id=str(job_id), target=job.target)
                hosts = await self.scanner.scan_network(
                    target=job.target,
                    ports=job.scan_options.get("ports"),
                    aggressive=job.scan_options.get("aggressive", False),
                )

                # Process results
                asset_svc = AssetService(db, self.producer)
                new_count = 0
                updated_count = 0

                for host in hosts:
                    try:
                        asset, is_new = await asset_svc.upsert_from_scan(host, job_id)
                        await asset_svc.publish_asset_discovered(asset, is_new, str(job_id))
                        if is_new:
                            new_count += 1
                        else:
                            updated_count += 1
                    except Exception as e:
                        logger.error(
                            "asset_upsert_failed",
                            ip=host.ip_address,
                            error=str(e),
                        )

                # Mark job complete
                job.status = "completed"
                job.completed_at = datetime.now(timezone.utc)
                job.hosts_discovered = len(hosts)
                job.hosts_new = new_count
                job.hosts_updated = updated_count
                await db.commit()

                logger.info(
                    "scan_completed",
                    job_id=str(job_id),
                    total=len(hosts),
                    new=new_count,
                    updated=updated_count,
                )

        except Exception as e:
            logger.error("scan_job_failed", job_id=str(job_id), error=str(e))
            await self._update_job_status(job_id, "failed", str(e))
        finally:
            _running_scans.discard(job_id)

    async def _update_job_status(
        self, job_id: uuid.UUID, status: str, error: str | None = None
    ) -> None:
        async with self.session_factory() as db:
            result = await db.execute(select(ScanJob).where(ScanJob.id == job_id))
            job = result.scalar_one_or_none()
            if job:
                job.status = status
                job.error_message = error
                job.completed_at = datetime.now(timezone.utc)
                await db.commit()
