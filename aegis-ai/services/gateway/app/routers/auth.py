"""
Authentication endpoints.
POST /auth/login, /auth/refresh, /auth/logout, GET /auth/me
"""
from typing import Annotated

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, Request

import sys
sys.path.insert(0, "/shared/python")
from aegis_common.logging import get_logger

from app.config import GatewaySettings, get_settings
from app.database import DBSession
from app.dependencies import CurrentUser, get_redis
from app.models.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    LoginResponse,
    RefreshRequest,
    RefreshResponse,
    UserRead,
)
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])
logger = get_logger(__name__)


@router.post("/login", response_model=LoginResponse, summary="Authenticate and receive tokens")
async def login(
    body: LoginRequest,
    request: Request,
    db: DBSession,
    redis: Annotated[aioredis.Redis, Depends(get_redis)],
    settings: Annotated[GatewaySettings, Depends(get_settings)],
) -> LoginResponse:
    """
    Authenticate with email and password.
    Returns access token (short-lived) and refresh token (long-lived).
    Store the refresh token securely — use it to get new access tokens.
    """
    svc = AuthService(db, redis, settings)
    return await svc.login(body.email, body.password, request)


@router.post("/refresh", response_model=RefreshResponse, summary="Get a new access token")
async def refresh(
    body: RefreshRequest,
    db: DBSession,
    redis: Annotated[aioredis.Redis, Depends(get_redis)],
    settings: Annotated[GatewaySettings, Depends(get_settings)],
) -> RefreshResponse:
    """Exchange a valid refresh token for a new short-lived access token."""
    svc = AuthService(db, redis, settings)
    return await svc.refresh(body.refresh_token)


@router.post("/logout", summary="Invalidate current session")
async def logout(
    current_user: CurrentUser,
    request: Request,
    db: DBSession,
    redis: Annotated[aioredis.Redis, Depends(get_redis)],
    settings: Annotated[GatewaySettings, Depends(get_settings)],
) -> dict:
    """
    Invalidate all tokens for the current user session.
    The access token JTI is added to Redis blocklist immediately.
    """
    # Extract JTI from the Authorization header token
    from fastapi.security import HTTPBearer
    from aegis_common.auth import decode_token

    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "")
    payload = decode_token(token, settings.jwt_secret_key, settings.jwt_algorithm)

    svc = AuthService(db, redis, settings)
    await svc.logout(current_user, payload.jti)
    return {"message": "Successfully logged out"}


@router.get("/me", response_model=UserRead, summary="Get current user profile")
async def get_me(current_user: CurrentUser) -> UserRead:
    """Return the authenticated user's profile."""
    return UserRead.model_validate(current_user)
