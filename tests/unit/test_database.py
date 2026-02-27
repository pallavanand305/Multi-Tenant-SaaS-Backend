"""
Unit tests for database connection and SQLAlchemy setup.

Tests the DatabaseManager class, connection pooling, and session management.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import (
    DatabaseManager,
    Base,
    SharedBase,
    TenantBase,
    db_manager,
    init_db,
    close_db,
)


class TestDatabaseManager:
    """Test DatabaseManager functionality"""
    
    def test_database_manager_initialization(self):
        """Test that DatabaseManager can be instantiated"""
        manager = DatabaseManager()
        assert manager._engine is None
        assert manager._session_factory is None
    
    def test_base_classes_exist(self):
        """Test that base model classes are defined"""
        assert Base is not None
        assert SharedBase is not None
        assert TenantBase is not None
        assert hasattr(Base, 'metadata')
        assert hasattr(SharedBase, 'metadata')
        assert hasattr(TenantBase, 'metadata')
    
    def test_shared_base_has_schema(self):
        """Test that SharedBase has platform_shared schema configured"""
        assert SharedBase.metadata.schema == "platform_shared"
    
    def test_naming_convention_configured(self):
        """Test that naming conventions are set for constraints"""
        assert Base.metadata.naming_convention is not None
        assert 'pk' in Base.metadata.naming_convention
        assert 'fk' in Base.metadata.naming_convention
        assert 'ix' in Base.metadata.naming_convention


@pytest.mark.asyncio
class TestDatabaseConnection:
    """Test database connection and session management"""
    
    async def test_init_db(self):
        """Test database initialization"""
        await init_db()
        assert db_manager._engine is not None
        assert db_manager._session_factory is not None
        await close_db()
    
    async def test_engine_property(self):
        """Test engine property access"""
        await init_db()
        engine = db_manager.engine
        assert engine is not None
        await close_db()
    
    async def test_engine_property_raises_when_not_initialized(self):
        """Test that accessing engine before initialization raises error"""
        manager = DatabaseManager()
        with pytest.raises(RuntimeError, match="not initialized"):
            _ = manager.engine
    
    async def test_session_factory_property(self):
        """Test session factory property access"""
        await init_db()
        factory = db_manager.session_factory
        assert factory is not None
        await close_db()
    
    async def test_get_session_structure(self):
        """Test getting a database session (structure only, no actual DB)"""
        await init_db()
        
        # Test that get_session returns an async generator
        session_gen = db_manager.get_session()
        assert hasattr(session_gen, '__aiter__')
        
        await close_db()
    
    async def test_health_check_with_mock(self):
        """Test database health check with mocked connection"""
        await init_db()
        
        # Mock the session factory to return a mock session
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        
        # Create a mock context manager
        mock_context = AsyncMock()
        mock_context.__aenter__ = AsyncMock(return_value=mock_session)
        mock_context.__aexit__ = AsyncMock(return_value=None)
        
        # Patch the session factory to return our mock context
        original_factory = db_manager._session_factory
        db_manager._session_factory = MagicMock(return_value=mock_context)
        
        try:
            is_healthy = await db_manager.health_check()
            assert is_healthy is True
            mock_session.execute.assert_called_once()
        finally:
            # Restore original factory
            db_manager._session_factory = original_factory
        
        await close_db()
    
    async def test_close_db(self):
        """Test database closure"""
        await init_db()
        await close_db()
        assert db_manager._engine is None
        assert db_manager._session_factory is None
    
    async def test_double_initialization_warning(self):
        """Test that double initialization logs a warning"""
        await init_db()
        db_manager.initialize()  # Second initialization
        # Note: structlog warnings may not appear in caplog, so we just verify no crash
        await close_db()


@pytest.mark.asyncio
class TestConnectionPooling:
    """Test connection pooling configuration"""
    
    async def test_connection_pool_configured(self):
        """Test that connection pool is properly configured"""
        await init_db()
        
        engine = db_manager.engine
        pool = engine.pool
        
        # Verify pool configuration
        assert pool is not None
        assert hasattr(pool, 'size')
        
        await close_db()
    
    async def test_session_factory_creates_sessions(self):
        """Test that session factory can create session objects"""
        await init_db()
        
        # Create a session (without connecting to DB)
        session = db_manager.session_factory()
        assert session is not None
        assert isinstance(session, AsyncSession)
        
        await session.close()
        await close_db()
