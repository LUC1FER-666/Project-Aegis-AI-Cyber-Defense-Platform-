"""
Authentication business logic.
Separated from routes for testability.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import redis.asyncio as aioredis
from fastapi import HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import sys
sys.path.insert(0, "/shared/python")
from aegis_common.auth import (
    TokenValidationError,
    create_token_pair,
    decode_token,
    hash_password,
    verify_password,
)
from aegis_common.logging import get_logger
from aegis_common.models import UserRole

from app.config import GatewaySettings
from app.models.db import AuditLog, User, UserSession
from app.models.schemas import LoginResponse, RefreshResponse, UserRead

logger = get_logger(__name__)


class AuthService:
    def __init__(
        self,
        db: AsyncSession,
        redis: aioredis.Redis,
        settings: GatewaySettings,
    ) -> None:
        self.db = db
        self.redis = redis
        self.settings = settings

    async def login(
        self, email: str, password: str, request: Request
    ) -> LoginResponse:
        # 1. Find user
        result = await self.db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()

        if user is None or not verify_password(password, user.hashed_password):
            await self._audit(None, "auth.login_failed", ip=self._get_ip(request))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is disabled",
            )

        # 2. Issue tokens
        token_pair = create_token_pair(
            user_id=user.id,
            email=user.email,
            role=UserRole(user.role),
            secret_key=self.settings.jwt_secret_key,
            algorithm=self.settings.jwt_algorithm,
            access_expire_minutes=self.settings.jwt_access_token_expire_minutes,
            refresh_expire_days=self.settings.jwt_refresh_token_expire_days,
        )

        # 3. Decode refresh token to get JTI for session tracking
        refresh_payload = decode_token(
            token_pair.refresh_token,
            self.settings.jwt_secret_key,
            self.settings.jwt_algorithm,
            expected_type="refresh",
        )

        # 4. Persist session
        session = UserSession(
            user_id=user.id,
            jti=refresh_payload.jti,
            ip_address=self._get_ip(request),
            user_agent=request.headers.get("User-Agent"),
            expires_at=refresh_payload.exp,
        )
        self.db.add(session)

        # 5. Update last login
        user.last_login = datetime.now(timezone.utc)

        await self.db.flush()
        await self._audit(user.id, "auth.login_success", ip=self._get_ip(request))

        logger.info("user_logged_in", user_id=str(user.id), email=user.email)

        return LoginResponse(
            access_token=token_pair.access_token,
            refresh_token=token_pair.refresh_token,
            expires_in=token_pair.expires_in,
            user=UserRead.model_validate(user),
        )

    async def refresh(self, refresh_token: str) -> RefreshResponse:
        """Exchange a valid refresh token for a new access token."""
        try:
            payload = decode_token(
                refresh_token,
                self.settings.jwt_secret_key,
                self.settings.jwt_algorithm,
                expected_type="refresh",
            )
        except TokenValidationError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token",
            )

        # Check revocation
        if await self.redis.get(f"revoked_jti:{payload.jti}"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
            )

        # Verify session still active in DB
        result = await self.db.execute(
            select(UserSession).where(
                UserSession.jti == payload.jti,
                UserSession.is_active == True,  # noqa: E712
            )
        )
        session = result.scalar_one_or_none()
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session not found or revoked",
            )

        # Issue new access token only
        from aegis_common.auth import create_access_token
        new_access_token = create_access_token(
            user_id=uuid.UUID(payload.sub),
            email=payload.email,
            role=payload.role,
            secret_key=self.settings.jwt_secret_key,
            algorithm=self.settings.jwt_algorithm,
            expire_minutes=self.settings.jwt_access_token_expire_minutes,
        )

        return RefreshResponse(
            access_token=new_access_token,
            expires_in=self.settings.jwt_access_token_expire_minutes * 60,
        )

    async def logout(self, user: User, jti: str) -> None:
        """Revoke the current access token's JTI via Redis."""
        # Add to Redis blocklist with TTL matching token expiry
        ttl = self.settings.jwt_access_token_expire_minutes * 60
        await self.redis.setex(f"revoked_jti:{jti}", ttl, "1")

        # Deactivate sessions for this user
        result = await self.db.execute(
            select(UserSession).where(
                UserSession.user_id == user.id,
                UserSession.is_active == True,  # noqa: E712
            )
        )
        sessions = result.scalars().all()
        for session in sessions:
            session.is_active = False
            session.revoked_at = datetime.now(timezone.utc)
            # Also revoke refresh token JTIs
            await self.redis.setex(
                f"revoked_jti:{session.jti}",
                self.settings.jwt_refresh_token_expire_days * 86400,
                "1",
            )

        await self._audit(user.id, "auth.logout")
        logger.info("user_logged_out", user_id=str(user.id))

    async def _audit(
        self,
        user_id: uuid.UUID | None,
        action: str,
        ip: str | None = None,
        details: dict | None = None,
    ) -> None:
        log = AuditLog(
            user_id=user_id,
            action=action,
            ip_address=ip,
            details=json.dumps(details) if details else None,
        )
        self.db.add(log)

    def _get_ip(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"
