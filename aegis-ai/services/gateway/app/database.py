"""
Async SQLAlchemy database setup.
Each request gets its own session via FastAPI dependency injection.
"""
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import get_settings

settings = get_settings()

# ---------------------------------------------------------------------------
# Engine — connection pool tuned for a single-service workload
# ---------------------------------------------------------------------------
engine = create_async_engine(
    settings.database_url,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,         # Detect dead connections before using them
    pool_recycle=3600,          # Recycle connections every hour
    echo=settings.environment == "development",  # SQL logging in dev only
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,     # Don't expire instances after commit
    autoflush=False,
)


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: yields an async database session per request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# Type alias for clean dependency injection in route handlers
DBSession = Annotated[AsyncSession, Depends(get_db)]
