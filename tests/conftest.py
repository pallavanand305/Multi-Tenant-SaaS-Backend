"""
Pytest Configuration and Fixtures

This module provides shared fixtures and configuration for all tests.
"""

import pytest
import asyncio
from typing import AsyncGenerator, Generator
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool

from main import app
from app.config import settings


# Configure pytest-asyncio
pytest_plugins = ('pytest_asyncio',)


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="function")
def client() -> TestClient:
    """Create a test client for the FastAPI application"""
    return TestClient(app)


@pytest.fixture(scope="session")
async def test_db_engine():
    """Create a test database engine"""
    # Use a separate test database
    test_db_url = settings.DATABASE_URL.replace("/saas_platform", "/saas_platform_test")
    
    engine = create_async_engine(
        test_db_url,
        poolclass=NullPool,
        echo=False
    )
    
    yield engine
    
    await engine.dispose()


@pytest.fixture(scope="function")
async def db_session(test_db_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session"""
    async_session = async_sessionmaker(
        test_db_engine,
        class_=AsyncSession,
        expire_on_commit=False
    )
    
    async with async_session() as session:
        yield session
        await session.rollback()


@pytest.fixture(scope="function")
def mock_tenant_id() -> str:
    """Provide a mock tenant ID for testing"""
    return "tenant_test123"


@pytest.fixture(scope="function")
def mock_user_id() -> str:
    """Provide a mock user ID for testing"""
    return "user_test456"


# Hypothesis settings for property-based tests
from hypothesis import settings as hypothesis_settings

hypothesis_settings.register_profile(
    "default",
    max_examples=100,
    deadline=None,
    print_blob=True
)

hypothesis_settings.register_profile(
    "ci",
    max_examples=1000,
    deadline=None
)

hypothesis_settings.load_profile("default")
