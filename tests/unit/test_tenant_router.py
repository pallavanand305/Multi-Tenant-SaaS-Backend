"""
Unit tests for TenantRouter class.

Tests tenant-specific database session management, schema routing,
tenant validation, and schema creation.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.tenant_router import TenantRouter
from app.database import db_manager, init_db, close_db


class TestTenantRouterInitialization:
    """Test TenantRouter initialization"""
    
    @pytest.mark.asyncio
    async def test_tenant_router_initialization(self):
        """Test that TenantRouter can be instantiated with engine"""
        await init_db()
        
        router = TenantRouter(db_manager.engine)
        assert router.engine is not None
        assert router.session_factory is not None
        
        await close_db()
    
    def test_tenant_router_requires_engine(self):
        """Test that TenantRouter requires an engine parameter"""
        with pytest.raises(TypeError):
            TenantRouter()


@pytest.mark.asyncio
class TestGetSession:
    """Test get_session method"""
    
    async def test_get_session_creates_session(self):
        """Test that get_session creates a database session"""
        await init_db()
        router = TenantRouter(db_manager.engine)
        
        # Mock the session to avoid actual database connection
        mock_session = AsyncMock(spec=AsyncSession)
        mock_session.execute = AsyncMock()
        mock_session.close = AsyncMock()
        
        # Mock the session factory
        original_factory = router.session_factory
        router.session_factory = MagicMock(return_value=mock_session)
        
        try:
            session = await router.get_session("test_tenant")
            assert session is not None
            assert session == mock_session
            
            # Verify execute was called to set search_path
            mock_session.execute.assert_called_once()
        finally:
            router.session_factory = original_factory
        
        await close_db()
    
    async def test_get_session_validates_tenant_id(self):
        """Test that get_session validates tenant_id parameter"""
        await init_db()
        router = TenantRouter(db_manager.engine)
        
        # Empty tenant_id
        with pytest.raises(ValueError, match="non-empty string"):
            await router.get_session("")
        
        # None tenant_id
        with pytest.raises(ValueError, match="non-empty string"):
            await router.get_session(None)
        
        # Invalid characters
        with pytest.raises(ValueError, match="invalid characters"):
            await router.get_session("tenant'; DROP TABLE users; --")
        
        await close_db()
    
    async def test_get_session_allows_valid_tenant_ids(self):
        """Test that get_session accepts valid tenant_id formats"""
        await init_db()
        router = TenantRouter(db_manager.engine)
        
        # Mock the session to avoid actual database connection
        mock_session = AsyncMock(spec=AsyncSession)
        mock_session.execute = AsyncMock()
        mock_session.close = AsyncMock()
        
        # Mock the session factory
        original_factory = router.session_factory
        router.session_factory = MagicMock(return_value=mock_session)
        
        try:
            # Alphanumeric
            session1 = await router.get_session("tenant123")
            assert session1 is not None
            
            # With underscores
            session2 = await router.get_session("tenant_abc_123")
            assert session2 is not None
            
            # Verify execute was called for both
            assert mock_session.execute.call_count == 2
        finally:
            router.session_factory = original_factory
        
        await close_db()
    
    async def test_get_session_sets_search_path(self):
        """Test that get_session sets PostgreSQL search_path"""
        await init_db()
        router = TenantRouter(db_manager.engine)
        
        # Mock the session execute method to capture the SQL
        mock_session = AsyncMock(spec=AsyncSession)
        mock_session.execute = AsyncMock()
        mock_session.close = AsyncMock()
        
        # Mock the session factory
        original_factory = router.session_factory
        router.session_factory = MagicMock(return_value=mock_session)
        
        try:
            session = await router.get_session("test_tenant")
            
            # Verify execute was called with SET search_path
            mock_session.execute.assert_called_once()
            call_args = mock_session.execute.call_args[0][0]
            assert "SET search_path TO tenant_test_tenant, public" in str(call_args)
            
        finally:
            router.session_factory = original_factory
        
        await close_db()
    
    async def test_get_session_closes_on_error(self):
        """Test that session is closed if search_path setting fails"""
        await init_db()
        router = TenantRouter(db_manager.engine)
        
        # Mock session that raises error on execute
        mock_session = AsyncMock(spec=AsyncSession)
        mock_session.execute = AsyncMock(side_effect=Exception("Database error"))
        mock_session.close = AsyncMock()
        
        # Mock the session factory
        original_factory = router.session_factory
        router.session_factory = MagicMock(return_value=mock_session)
        
        try:
            with pytest.raises(Exception, match="Database error"):
                await router.get_session("test_tenant")
            
            # Verify session was closed
            mock_session.close.assert_called_once()
            
        finally:
            router.session_factory = original_factory
        
        await close_db()


@pytest.mark.asyncio
class TestValidateTenant:
    """Test validate_tenant method"""
    
    async def test_validate_tenant_with_invalid_input(self):
        """Test that validate_tenant handles invalid input gracefully"""
        await init_db()
        router = TenantRouter(db_manager.engine)
        
        # Empty tenant_id
        result = await router.validate_tenant("")
        assert result is False
        
        # None tenant_id
        result = await router.validate_tenant(None)
        assert result is False
        
        await close_db()
    
    async def test_validate_tenant_returns_false_for_nonexistent(self):
        """Test that validate_tenant returns False for non-existent tenant"""
        await init_db()
        router = TenantRouter(db_manager.engine)
        
        # Mock the session to return no results
        mock_session = AsyncMock()
        mock_result = AsyncMock()
        mock_result.fetchone = MagicMock(return_value=None)
        mock_session.execute = AsyncMock(return_value=mock_result)
        
        # Create mock context manager
        mock_context = AsyncMock()
        mock_context.__aenter__ = AsyncMock(return_value=mock_session)
        mock_context.__aexit__ = AsyncMock(return_value=None)
        
        # Mock the session factory
        original_factory = router.session_factory
        router.session_factory = MagicMock(return_value=mock_context)
        
        try:
            result = await router.validate_tenant("nonexistent_tenant")
            assert result is False
        finally:
            router.session_factory = original_factory
        
        await close_db()
    
    async def test_validate_tenant_returns_true_for_active_tenant(self):
        """Test that validate_tenant returns True for active tenant"""
        await init_db()
        router = TenantRouter(db_manager.engine)
        
        # Mock the session to return active tenant
        mock_session = AsyncMock()
        mock_result = AsyncMock()
        mock_result.fetchone = MagicMock(return_value=("tenant_123", "active"))
        mock_session.execute = AsyncMock(return_value=mock_result)
        
        # Create mock context manager
        mock_context = AsyncMock()
        mock_context.__aenter__ = AsyncMock(return_value=mock_session)
        mock_context.__aexit__ = AsyncMock(return_value=None)
        
        # Mock the session factory
        original_factory = router.session_factory
        router.session_factory = MagicMock(return_value=mock_context)
        
        try:
            result = await router.validate_tenant("tenant_123")
            assert result is True
        finally:
            router.session_factory = original_factory
        
        await close_db()
    
    async def test_validate_tenant_returns_false_for_inactive_tenant(self):
        """Test that validate_tenant returns False for inactive tenant"""
        await init_db()
        router = TenantRouter(db_manager.engine)
        
        # Mock the session to return inactive tenant
        mock_session = AsyncMock()
        mock_result = AsyncMock()
        mock_result.fetchone = MagicMock(return_value=("tenant_123", "suspended"))
        mock_session.execute = AsyncMock(return_value=mock_result)
        
        # Create mock context manager
        mock_context = AsyncMock()
        mock_context.__aenter__ = AsyncMock(return_value=mock_session)
        mock_context.__aexit__ = AsyncMock(return_value=None)
        
        # Mock the session factory
        original_factory = router.session_factory
        router.session_factory = MagicMock(return_value=mock_context)
        
        try:
            result = await router.validate_tenant("tenant_123")
            assert result is False
        finally:
            router.session_factory = original_factory
        
        await close_db()
    
    async def test_validate_tenant_handles_database_errors(self):
        """Test that validate_tenant handles database errors gracefully"""
        await init_db()
        router = TenantRouter(db_manager.engine)
        
        # Mock the session to raise an error
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(side_effect=Exception("Database error"))
        
        # Create mock context manager
        mock_context = AsyncMock()
        mock_context.__aenter__ = AsyncMock(return_value=mock_session)
        mock_context.__aexit__ = AsyncMock(return_value=None)
        
        # Mock the session factory
        original_factory = router.session_factory
        router.session_factory = MagicMock(return_value=mock_context)
        
        try:
            result = await router.validate_tenant("tenant_123")
            assert result is False
        finally:
            router.session_factory = original_factory
        
        await close_db()


@pytest.mark.asyncio
class TestCreateTenantSchema:
    """Test create_tenant_schema method"""
    
    async def test_create_tenant_schema_validates_tenant_id(self):
        """Test that create_tenant_schema validates tenant_id"""
        await init_db()
        router = TenantRouter(db_manager.engine)
        
        # Empty tenant_id
        with pytest.raises(ValueError, match="non-empty string"):
            await router.create_tenant_schema("")
        
        # None tenant_id
        with pytest.raises(ValueError, match="non-empty string"):
            await router.create_tenant_schema(None)
        
        # Invalid characters
        with pytest.raises(ValueError, match="invalid characters"):
            await router.create_tenant_schema("tenant'; DROP SCHEMA public; --")
        
        await close_db()
    
    async def test_create_tenant_schema_executes_sql(self):
        """Test that create_tenant_schema executes schema creation SQL"""
        await init_db()
        router = TenantRouter(db_manager.engine)
        
        # Mock the session
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.commit = AsyncMock()
        mock_session.rollback = AsyncMock()
        
        # Create mock context manager
        mock_context = AsyncMock()
        mock_context.__aenter__ = AsyncMock(return_value=mock_session)
        mock_context.__aexit__ = AsyncMock(return_value=None)
        
        # Mock the session factory
        original_factory = router.session_factory
        router.session_factory = MagicMock(return_value=mock_context)
        
        try:
            await router.create_tenant_schema("test_tenant")
            
            # Verify execute was called multiple times (schema + tables)
            assert mock_session.execute.call_count > 5
            
            # Verify commit was called
            mock_session.commit.assert_called_once()
            
            # Verify rollback was not called
            mock_session.rollback.assert_not_called()
            
        finally:
            router.session_factory = original_factory
        
        await close_db()
    
    async def test_create_tenant_schema_creates_all_tables(self):
        """Test that create_tenant_schema creates all required tables"""
        await init_db()
        router = TenantRouter(db_manager.engine)
        
        # Mock the session
        mock_session = AsyncMock()
        executed_sql = []
        
        async def capture_execute(sql, *args, **kwargs):
            executed_sql.append(str(sql))
        
        mock_session.execute = AsyncMock(side_effect=capture_execute)
        mock_session.commit = AsyncMock()
        
        # Create mock context manager
        mock_context = AsyncMock()
        mock_context.__aenter__ = AsyncMock(return_value=mock_session)
        mock_context.__aexit__ = AsyncMock(return_value=None)
        
        # Mock the session factory
        original_factory = router.session_factory
        router.session_factory = MagicMock(return_value=mock_context)
        
        try:
            await router.create_tenant_schema("test_tenant")
            
            # Verify all required tables are created
            all_sql = " ".join(executed_sql)
            assert "CREATE SCHEMA" in all_sql
            assert "users" in all_sql
            assert "api_keys" in all_sql
            assert "rbac_policies" in all_sql
            assert "resources" in all_sql
            assert "jobs" in all_sql
            assert "audit_logs" in all_sql
            
        finally:
            router.session_factory = original_factory
        
        await close_db()
    
    async def test_create_tenant_schema_rolls_back_on_error(self):
        """Test that create_tenant_schema rolls back on error"""
        await init_db()
        router = TenantRouter(db_manager.engine)
        
        # Mock the session to fail on commit
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.commit = AsyncMock(side_effect=Exception("Commit failed"))
        mock_session.rollback = AsyncMock()
        
        # Create mock context manager
        mock_context = AsyncMock()
        mock_context.__aenter__ = AsyncMock(return_value=mock_session)
        mock_context.__aexit__ = AsyncMock(return_value=None)
        
        # Mock the session factory
        original_factory = router.session_factory
        router.session_factory = MagicMock(return_value=mock_context)
        
        try:
            with pytest.raises(Exception, match="Commit failed"):
                await router.create_tenant_schema("test_tenant")
            
            # Verify rollback was called
            mock_session.rollback.assert_called_once()
            
        finally:
            router.session_factory = original_factory
        
        await close_db()
