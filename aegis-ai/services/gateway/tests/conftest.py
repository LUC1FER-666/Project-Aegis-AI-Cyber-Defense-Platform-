"""
Shared pytest fixtures for gateway tests.
"""
from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from typing import Any

import pytest
import pytest_asyncio

# Set test env vars before importing app modules
os.environ.setdefault("POSTGRES_PASSWORD", "aegis_dev_password")
os.environ.setdefault("POSTGRES_DB", "aegis")
os.environ.setdefault("POSTGRES_HOST", "localhost")
os.environ.setdefault("NEO4J_PASSWORD", "aegis_dev_password")
os.environ.setdefault(
    "JWT_SECRET_KEY",
    "test_secret_minimum_64_chars_long_for_testing_purposes_xxxxxxxxxxx"
)
os.environ.setdefault("ENVIRONMENT", "development")


@pytest.fixture(scope="session")
def event_loop():
    """Create a single event loop for the entire test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
