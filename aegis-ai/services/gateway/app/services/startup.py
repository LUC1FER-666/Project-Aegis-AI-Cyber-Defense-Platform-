"""
Startup tasks that run once when the gateway boots.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import sys
sys.path.insert(0, "/shared/python")
from aegis_common.auth import hash_password
from aegis_common.logging import get_logger
from aegis_common.models import UserRole

from app.models.db import User

logger = get_logger(__name__)


async def create_initial_admin(settings) -> None:
    """
    Create the default admin account on first startup.
    Skips if admin already exists.
    """
    engine = create_async_engine(settings.database_url)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with session_factory() as session:
        result = await session.execute(
            select(User).where(User.email == settings.initial_admin_email)
        )
        if result.scalar_one_or_none() is not None:
            logger.info("initial_admin_already_exists")
            await engine.dispose()
            return

        admin = User(
            email=settings.initial_admin_email,
            username="admin",
            hashed_password=hash_password(settings.initial_admin_password),
            full_name="Aegis Administrator",
            role=UserRole.ADMIN.value,
            is_active=True,
            is_verified=True,
            must_change_password=True,  # Force password change on first login
        )
        session.add(admin)
        await session.commit()

        logger.info(
            "initial_admin_created",
            email=settings.initial_admin_email,
            note="Change password immediately",
        )

    await engine.dispose()
