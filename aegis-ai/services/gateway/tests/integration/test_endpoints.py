"""
Integration tests for gateway API endpoints.
Uses httpx AsyncClient with a test database.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

# These tests require a running postgres and redis — run via:
# docker compose up -d postgres redis
# pytest services/gateway/tests/integration/

pytestmark = pytest.mark.asyncio


@pytest.fixture
def anyio_backend():
    return "asyncio"


class TestAuthEndpoints:
    """Test the /api/v1/auth/* endpoints."""

    async def test_login_success(self, client: AsyncClient):
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "admin@aegis.local", "password": "AegisAdmin@2024!"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert "user" in data
        assert data["user"]["email"] == "admin@aegis.local"

    async def test_login_wrong_password(self, client: AsyncClient):
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "admin@aegis.local", "password": "wrong_password"},
        )
        assert response.status_code == 401

    async def test_login_nonexistent_user(self, client: AsyncClient):
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@aegis.local", "password": "password"},
        )
        assert response.status_code == 401

    async def test_get_me_authenticated(self, client: AsyncClient, admin_token: str):
        response = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "admin@aegis.local"
        assert data["role"] == "admin"

    async def test_get_me_unauthenticated(self, client: AsyncClient):
        response = await client.get("/api/v1/auth/me")
        assert response.status_code == 403  # HTTPBearer returns 403 when no creds

    async def test_refresh_token(self, client: AsyncClient):
        # Login to get tokens
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "admin@aegis.local", "password": "AegisAdmin@2024!"},
        )
        refresh_token = login_resp.json()["refresh_token"]

        # Exchange for new access token
        refresh_resp = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert refresh_resp.status_code == 200
        assert "access_token" in refresh_resp.json()

    async def test_logout(self, client: AsyncClient, admin_token: str):
        response = await client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200


class TestHealthEndpoint:
    async def test_health_returns_200(self, client: AsyncClient):
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "gateway"
        assert "checks" in data
