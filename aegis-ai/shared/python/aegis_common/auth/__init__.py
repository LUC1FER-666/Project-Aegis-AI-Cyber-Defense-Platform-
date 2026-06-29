"""
JWT authentication utilities.
Used by the gateway to issue tokens and by all other services to validate them.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
from jose import JWTError, jwt
from pydantic import BaseModel

from aegis_common.models import UserRole

# ---------------------------------------------------------------------------
# Password hashing
# Using bcrypt directly — passlib is unmaintained and broken on Python 3.12+
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Hash a password using bcrypt with a random salt."""
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Token models
# ---------------------------------------------------------------------------

class TokenPayload(BaseModel):
    """Claims embedded in the JWT."""
    sub: str                  # user ID (UUID string)
    email: str
    role: UserRole
    jti: str                  # JWT ID — for revocation
    type: str                 # "access" | "refresh"
    iat: datetime
    exp: datetime


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int           # seconds until access token expires


# ---------------------------------------------------------------------------
# Token creation
# ---------------------------------------------------------------------------

def create_access_token(
    user_id: uuid.UUID,
    email: str,
    role: UserRole,
    secret_key: str,
    algorithm: str,
    expire_minutes: int,
) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "email": email,
        "role": role.value if hasattr(role, "value") else role,
        "jti": str(uuid.uuid4()),
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=expire_minutes),
    }
    return jwt.encode(payload, secret_key, algorithm=algorithm)


def create_refresh_token(
    user_id: uuid.UUID,
    email: str,
    role: UserRole,
    secret_key: str,
    algorithm: str,
    expire_days: int,
) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "email": email,
        "role": role.value if hasattr(role, "value") else role,
        "jti": str(uuid.uuid4()),
        "type": "refresh",
        "iat": now,
        "exp": now + timedelta(days=expire_days),
    }
    return jwt.encode(payload, secret_key, algorithm=algorithm)


def create_token_pair(
    user_id: uuid.UUID,
    email: str,
    role: UserRole,
    secret_key: str,
    algorithm: str,
    access_expire_minutes: int,
    refresh_expire_days: int,
) -> TokenPair:
    return TokenPair(
        access_token=create_access_token(
            user_id, email, role, secret_key, algorithm, access_expire_minutes
        ),
        refresh_token=create_refresh_token(
            user_id, email, role, secret_key, algorithm, refresh_expire_days
        ),
        expires_in=access_expire_minutes * 60,
    )


# ---------------------------------------------------------------------------
# Token validation
# ---------------------------------------------------------------------------

class TokenValidationError(Exception):
    """Raised when a token is invalid, expired, or revoked."""
    pass


def decode_token(
    token: str,
    secret_key: str,
    algorithm: str,
    expected_type: str = "access",
) -> TokenPayload:
    """
    Decode and validate a JWT. Raises TokenValidationError on any failure.
    The caller is responsible for checking Redis revocation if needed.
    """
    try:
        raw = jwt.decode(token, secret_key, algorithms=[algorithm])
    except JWTError as e:
        raise TokenValidationError(f"Invalid token: {e}") from e

    if raw.get("type") != expected_type:
        raise TokenValidationError(
            f"Expected token type '{expected_type}', got '{raw.get('type')}'"
        )

    try:
        return TokenPayload(
            sub=raw["sub"],
            email=raw["email"],
            role=UserRole(raw["role"]),
            jti=raw["jti"],
            type=raw["type"],
            iat=datetime.fromtimestamp(raw["iat"], tz=timezone.utc),
            exp=datetime.fromtimestamp(raw["exp"], tz=timezone.utc),
        )
    except (KeyError, ValueError) as e:
        raise TokenValidationError(f"Malformed token payload: {e}") from e


# ---------------------------------------------------------------------------
# RBAC — permission checks
# ---------------------------------------------------------------------------

_ROLE_HIERARCHY: list[UserRole] = [
    UserRole.READ_ONLY,
    UserRole.EXECUTIVE,
    UserRole.SOC_ANALYST,
    UserRole.THREAT_HUNTER,
    UserRole.SOC_LEAD,
    UserRole.ADMIN,
]

_PERMISSIONS: dict[str, UserRole] = {
    "read:incidents": UserRole.READ_ONLY,
    "write:incidents": UserRole.SOC_ANALYST,
    "read:assets": UserRole.READ_ONLY,
    "write:assets": UserRole.SOC_ANALYST,
    "approve:response": UserRole.SOC_LEAD,
    "execute:response": UserRole.SOC_LEAD,
    "manage:rules": UserRole.SOC_LEAD,
    "read:threat_intel": UserRole.SOC_ANALYST,
    "manage:users": UserRole.ADMIN,
    "manage:settings": UserRole.ADMIN,
    "trigger:scan": UserRole.SOC_ANALYST,
    "read:reports": UserRole.READ_ONLY,
    "generate:reports": UserRole.SOC_ANALYST,
}


def has_permission(user_role: UserRole, permission: str) -> bool:
    required = _PERMISSIONS.get(permission)
    if required is None:
        return False
    try:
        user_level = _ROLE_HIERARCHY.index(user_role)
        required_level = _ROLE_HIERARCHY.index(required)
        return user_level >= required_level
    except ValueError:
        return False


def require_role(user_role: UserRole, minimum_role: UserRole) -> bool:
    try:
        return _ROLE_HIERARCHY.index(user_role) >= _ROLE_HIERARCHY.index(minimum_role)
    except ValueError:
        return False
