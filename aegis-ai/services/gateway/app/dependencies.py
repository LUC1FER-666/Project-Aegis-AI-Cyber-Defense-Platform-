"""
FastAPI dependency injection for authentication and authorization.
Import these into route handlers to enforce auth and RBAC.

Usage:
    @router.get("/incidents")
    async def list_incidents(
        current_user: CurrentUser,
        _: RequireSOCAnalyst,
    ):
        ...
"""
from __future__ import annotations

from typing import Annotated

import redis.asyncio as aioredis
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import sys
sys.path.insert(0, "/shared/python")
from aegis_common.auth import TokenValidationError, decode_token
from aegis_common.models import UserRole

from app.config import get_settings
from app.database import get_db
from app.models.db import User

settings = get_settings()
_bearer = HTTPBearer(auto_error=True)


# ---------------------------------------------------------------------------
# Redis client for token revocation checks
# ---------------------------------------------------------------------------

_redis_client: aioredis.Redis | None = None


async def get_redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = await aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )
    return _redis_client


# ---------------------------------------------------------------------------
# Core auth dependency
# ---------------------------------------------------------------------------

async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(_bearer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[aioredis.Redis, Depends(get_redis)],
) -> User:
    """
    Validate JWT, check revocation list, return User ORM object.
    Raises 401 on any failure.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_token(
            credentials.credentials,
            settings.jwt_secret_key,
            settings.jwt_algorithm,
            expected_type="access",
        )
    except TokenValidationError:
        raise credentials_exception

    # Check if JTI is revoked in Redis (fast path)
    revoked = await redis.get(f"revoked_jti:{payload.jti}")
    if revoked:
        raise credentials_exception

    # Load user from DB
    result = await db.execute(select(User).where(User.id == payload.sub))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise credentials_exception

    return user


# ---------------------------------------------------------------------------
# Typed annotations for cleaner route signatures
# ---------------------------------------------------------------------------

CurrentUser = Annotated[User, Depends(get_current_user)]


def require_role(minimum_role: UserRole):
    """
    Dependency factory: raises 403 if the current user's role is insufficient.

    Usage:
        @router.post("/rules")
        async def create_rule(
            current_user: CurrentUser,
            _: Annotated[None, Depends(require_role(UserRole.SOC_LEAD))],
        ):
    """
    async def _check(current_user: CurrentUser) -> None:
        role_hierarchy = [
            UserRole.READ_ONLY,
            UserRole.EXECUTIVE,
            UserRole.SOC_ANALYST,
            UserRole.THREAT_HUNTER,
            UserRole.SOC_LEAD,
            UserRole.ADMIN,
        ]
        try:
            user_level = role_hierarchy.index(UserRole(current_user.role))
            required_level = role_hierarchy.index(minimum_role)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {minimum_role.value}",
            )

    return Depends(_check)


# Convenience aliases
RequireAdmin = require_role(UserRole.ADMIN)
RequireSOCLead = require_role(UserRole.SOC_LEAD)
RequireSOCAnalyst = require_role(UserRole.SOC_ANALYST)
RequireThreatHunter = require_role(UserRole.THREAT_HUNTER)
