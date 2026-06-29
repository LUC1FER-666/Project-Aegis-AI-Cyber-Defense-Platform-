"""
Unit tests for auth service.
These test business logic in isolation — no real DB or Redis.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import sys
sys.path.insert(0, "/shared/python")
from aegis_common.auth import (
    create_token_pair,
    decode_token,
    hash_password,
    has_permission,
    require_role,
    verify_password,
)
from aegis_common.models import UserRole


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

class TestPasswordHashing:
    def test_hash_and_verify_success(self):
        password = "SecureP@ssword123"
        hashed = hash_password(password)
        assert verify_password(password, hashed)

    def test_wrong_password_fails(self):
        hashed = hash_password("correct_horse_battery")
        assert not verify_password("wrong_password", hashed)

    def test_hash_is_unique(self):
        password = "SamePassword1!"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        assert hash1 != hash2  # bcrypt uses random salt


# ---------------------------------------------------------------------------
# JWT tokens
# ---------------------------------------------------------------------------

SECRET = "test_secret_key_at_least_32_characters_long_for_testing"
ALGO = "HS256"


class TestJWT:
    def test_create_and_decode_access_token(self):
        user_id = uuid.uuid4()
        pair = create_token_pair(
            user_id=user_id,
            email="analyst@aegis.test",
            role=UserRole.SOC_ANALYST,
            secret_key=SECRET,
            algorithm=ALGO,
            access_expire_minutes=30,
            refresh_expire_days=7,
        )

        payload = decode_token(pair.access_token, SECRET, ALGO, expected_type="access")
        assert payload.sub == str(user_id)
        assert payload.email == "analyst@aegis.test"
        assert payload.role == UserRole.SOC_ANALYST
        assert payload.type == "access"

    def test_decode_refresh_token(self):
        user_id = uuid.uuid4()
        pair = create_token_pair(
            user_id=user_id,
            email="test@aegis.test",
            role=UserRole.ADMIN,
            secret_key=SECRET,
            algorithm=ALGO,
            access_expire_minutes=30,
            refresh_expire_days=7,
        )

        payload = decode_token(pair.refresh_token, SECRET, ALGO, expected_type="refresh")
        assert payload.type == "refresh"

    def test_wrong_token_type_raises(self):
        from aegis_common.auth import TokenValidationError

        user_id = uuid.uuid4()
        pair = create_token_pair(
            user_id=user_id,
            email="test@aegis.test",
            role=UserRole.SOC_ANALYST,
            secret_key=SECRET,
            algorithm=ALGO,
            access_expire_minutes=30,
            refresh_expire_days=7,
        )

        with pytest.raises(TokenValidationError, match="Expected token type 'refresh'"):
            decode_token(pair.access_token, SECRET, ALGO, expected_type="refresh")

    def test_wrong_secret_raises(self):
        from aegis_common.auth import TokenValidationError

        pair = create_token_pair(
            user_id=uuid.uuid4(),
            email="test@aegis.test",
            role=UserRole.SOC_ANALYST,
            secret_key=SECRET,
            algorithm=ALGO,
            access_expire_minutes=30,
            refresh_expire_days=7,
        )

        with pytest.raises(TokenValidationError):
            decode_token(pair.access_token, "wrong_secret", ALGO)

    def test_token_pair_expires_in(self):
        pair = create_token_pair(
            user_id=uuid.uuid4(),
            email="test@aegis.test",
            role=UserRole.SOC_ANALYST,
            secret_key=SECRET,
            algorithm=ALGO,
            access_expire_minutes=15,
            refresh_expire_days=7,
        )
        assert pair.expires_in == 15 * 60
        assert pair.token_type == "bearer"


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------

class TestRBAC:
    def test_admin_has_all_permissions(self):
        assert has_permission(UserRole.ADMIN, "manage:users")
        assert has_permission(UserRole.ADMIN, "approve:response")
        assert has_permission(UserRole.ADMIN, "read:incidents")

    def test_read_only_cannot_write(self):
        assert has_permission(UserRole.READ_ONLY, "read:incidents")
        assert not has_permission(UserRole.READ_ONLY, "write:incidents")
        assert not has_permission(UserRole.READ_ONLY, "approve:response")

    def test_soc_analyst_can_write_incidents(self):
        assert has_permission(UserRole.SOC_ANALYST, "write:incidents")
        assert not has_permission(UserRole.SOC_ANALYST, "approve:response")
        assert not has_permission(UserRole.SOC_ANALYST, "manage:users")

    def test_soc_lead_can_approve_response(self):
        assert has_permission(UserRole.SOC_LEAD, "approve:response")
        assert has_permission(UserRole.SOC_LEAD, "write:incidents")
        assert not has_permission(UserRole.SOC_LEAD, "manage:users")

    def test_unknown_permission_denied(self):
        assert not has_permission(UserRole.ADMIN, "nonexistent:permission")

    def test_require_role_hierarchy(self):
        assert require_role(UserRole.ADMIN, UserRole.SOC_ANALYST)
        assert require_role(UserRole.SOC_LEAD, UserRole.SOC_ANALYST)
        assert not require_role(UserRole.SOC_ANALYST, UserRole.SOC_LEAD)
        assert not require_role(UserRole.READ_ONLY, UserRole.SOC_ANALYST)
