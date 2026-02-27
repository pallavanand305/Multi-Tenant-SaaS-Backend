"""
Unit tests for AuthService

Tests the unified authentication service including JWT and API key integration,
credential verification, and tenant context extraction.

Requirements: 2.1, 2.3, 2.6, 4.1
"""

import pytest
import bcrypt
from uuid import uuid4
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from app.auth.auth_service import AuthService, TenantContext
from app.auth.jwt_handler import JWTHandler, TokenPayload, AuthenticationError
from app.auth.api_key_manager import APIKeyManager, APIKeyPayload, APIKeyError
from app.models.tenant import User, APIKey


class TestTenantContext:
    """Test TenantContext class"""
    
    def test_tenant_context_creation(self):
        """Test creating a tenant context"""
        context = TenantContext(
            tenant_id="tenant_123",
            user_id="user_456",
            role="admin",
            auth_method="jwt"
        )
        
        assert context.tenant_id == "tenant_123"
        assert context.user_id == "user_456"
        assert context.role == "admin"
        assert context.auth_method == "jwt"
        assert context.api_key_id is None
    
    def test_tenant_context_with_api_key(self):
        """Test creating a tenant context with API key"""
        key_id = uuid4()
        context = TenantContext(
            tenant_id="tenant_123",
            user_id="api_key",
            role="developer",
            auth_method="api_key",
            api_key_id=key_id
        )
        
        assert context.tenant_id == "tenant_123"
        assert context.user_id == "api_key"
        assert context.role == "developer"
        assert context.auth_method == "api_key"
        assert context.api_key_id == key_id
    
    def test_tenant_context_to_dict(self):
        """Test converting tenant context to dictionary"""
        key_id = uuid4()
        context = TenantContext(
            tenant_id="tenant_123",
            user_id="user_456",
            role="admin",
            auth_method="jwt",
            api_key_id=key_id
        )
        
        context_dict = context.to_dict()
        
        assert context_dict["tenant_id"] == "tenant_123"
        assert context_dict["user_id"] == "user_456"
        assert context_dict["role"] == "admin"
        assert context_dict["auth_method"] == "jwt"
        assert context_dict["api_key_id"] == str(key_id)
    
    def test_tenant_context_repr(self):
        """Test tenant context string representation"""
        context = TenantContext(
            tenant_id="tenant_123",
            user_id="user_456",
            role="admin",
            auth_method="jwt"
        )
        
        repr_str = repr(context)
        assert "tenant_123" in repr_str
        assert "user_456" in repr_str
        assert "admin" in repr_str
        assert "jwt" in repr_str


class TestAuthService:
    """Test AuthService class"""
    
    @pytest.fixture
    def mock_jwt_handler(self):
        """Create a mock JWT handler"""
        return MagicMock(spec=JWTHandler)
    
    @pytest.fixture
    def mock_api_key_manager(self):
        """Create a mock API key manager"""
        return MagicMock(spec=APIKeyManager)
    
    @pytest.fixture
    def auth_service(self, mock_jwt_handler, mock_api_key_manager):
        """Create an AuthService instance with mocked dependencies"""
        return AuthService(
            jwt_handler=mock_jwt_handler,
            api_key_manager=mock_api_key_manager
        )
    
    def test_auth_service_initialization(self, auth_service, mock_jwt_handler, mock_api_key_manager):
        """Test AuthService initialization"""
        assert auth_service.jwt_handler == mock_jwt_handler
        assert auth_service.api_key_manager == mock_api_key_manager
    
    def test_auth_service_default_initialization(self):
        """Test AuthService initialization with default dependencies"""
        with patch('app.auth.auth_service.JWTHandler') as mock_jwt_class, \
             patch('app.auth.auth_service.APIKeyManager') as mock_api_key_class:
            
            service = AuthService()
            
            mock_jwt_class.assert_called_once()
            mock_api_key_class.assert_called_once()
    
    def test_generate_jwt(self, auth_service, mock_jwt_handler):
        """Test JWT token generation"""
        mock_jwt_handler.generate_jwt.return_value = "test_token_123"
        
        token = auth_service.generate_jwt(
            user_id="user_123",
            tenant_id="tenant_abc",
            role="admin"
        )
        
        assert token == "test_token_123"
        mock_jwt_handler.generate_jwt.assert_called_once_with(
            "user_123",
            "tenant_abc",
            "admin"
        )
    
    def test_validate_jwt(self, auth_service, mock_jwt_handler):
        """Test JWT token validation"""
        mock_payload = TokenPayload(
            tenant_id="tenant_abc",
            user_id="user_123",
            role="admin",
            exp=int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
            iat=int(datetime.utcnow().timestamp())
        )
        mock_jwt_handler.validate_jwt.return_value = mock_payload
        
        payload = auth_service.validate_jwt("test_token")
        
        assert payload.tenant_id == "tenant_abc"
        assert payload.user_id == "user_123"
        assert payload.role == "admin"
        mock_jwt_handler.validate_jwt.assert_called_once_with("test_token")
    
    def test_validate_jwt_invalid_token(self, auth_service, mock_jwt_handler):
        """Test JWT validation with invalid token"""
        mock_jwt_handler.validate_jwt.side_effect = AuthenticationError(
            "INVALID_TOKEN",
            "Token is invalid"
        )
        
        with pytest.raises(AuthenticationError) as exc_info:
            auth_service.validate_jwt("invalid_token")
        
        assert exc_info.value.code == "INVALID_TOKEN"
    
    @pytest.mark.asyncio
    async def test_create_api_key(self, auth_service, mock_api_key_manager):
        """Test API key creation"""
        key_id = uuid4()
        mock_api_key = MagicMock()
        mock_api_key.id = key_id
        
        mock_api_key_manager.create_api_key = AsyncMock(
            return_value=(mock_api_key, "abc12345_secretkey")
        )
        
        db_session = AsyncMock()
        created_by = uuid4()
        
        result_id, full_key = await auth_service.create_api_key(
            db=db_session,
            tenant_id="tenant_abc",
            role="developer",
            name="Test Key",
            created_by=created_by
        )
        
        assert result_id == key_id
        assert full_key == "abc12345_secretkey"
        mock_api_key_manager.create_api_key.assert_called_once_with(
            db=db_session,
            tenant_id="tenant_abc",
            role="developer",
            name="Test Key",
            created_by=created_by
        )
    
    @pytest.mark.asyncio
    async def test_validate_api_key(self, auth_service, mock_api_key_manager):
        """Test API key validation"""
        key_id = uuid4()
        mock_payload = APIKeyPayload(
            key_id=key_id,
            tenant_id="tenant_abc",
            role="developer",
            name="Test Key"
        )
        
        mock_api_key_manager.validate_api_key = AsyncMock(return_value=mock_payload)
        
        db_session = AsyncMock()
        
        payload = await auth_service.validate_api_key(
            db=db_session,
            tenant_id="tenant_abc",
            key="abc12345_secretkey"
        )
        
        assert payload.key_id == key_id
        assert payload.tenant_id == "tenant_abc"
        assert payload.role == "developer"
        assert payload.name == "Test Key"
    
    @pytest.mark.asyncio
    async def test_validate_api_key_invalid(self, auth_service, mock_api_key_manager):
        """Test API key validation with invalid key"""
        mock_api_key_manager.validate_api_key = AsyncMock(
            side_effect=APIKeyError("INVALID_API_KEY", "Key is invalid")
        )
        
        db_session = AsyncMock()
        
        with pytest.raises(APIKeyError) as exc_info:
            await auth_service.validate_api_key(
                db=db_session,
                tenant_id="tenant_abc",
                key="invalid_key"
            )
        
        assert exc_info.value.code == "INVALID_API_KEY"
    
    @pytest.mark.asyncio
    async def test_revoke_api_key(self, auth_service, mock_api_key_manager):
        """Test API key revocation"""
        mock_api_key_manager.revoke_api_key = AsyncMock(return_value=True)
        
        db_session = AsyncMock()
        key_id = uuid4()
        
        result = await auth_service.revoke_api_key(
            db=db_session,
            tenant_id="tenant_abc",
            key_id=key_id
        )
        
        assert result is True
        mock_api_key_manager.revoke_api_key.assert_called_once_with(
            db=db_session,
            tenant_id="tenant_abc",
            key_id=key_id
        )
    
    def test_extract_tenant_context_from_jwt(self, auth_service, mock_jwt_handler):
        """Test extracting tenant context from JWT token"""
        mock_payload = TokenPayload(
            tenant_id="tenant_abc",
            user_id="user_123",
            role="admin",
            exp=int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
            iat=int(datetime.utcnow().timestamp())
        )
        mock_jwt_handler.validate_jwt.return_value = mock_payload
        
        context = auth_service.extract_tenant_context_from_jwt("test_token")
        
        assert isinstance(context, TenantContext)
        assert context.tenant_id == "tenant_abc"
        assert context.user_id == "user_123"
        assert context.role == "admin"
        assert context.auth_method == "jwt"
        assert context.api_key_id is None
    
    @pytest.mark.asyncio
    async def test_extract_tenant_context_from_api_key(self, auth_service, mock_api_key_manager):
        """Test extracting tenant context from API key"""
        key_id = uuid4()
        mock_payload = APIKeyPayload(
            key_id=key_id,
            tenant_id="tenant_abc",
            role="developer",
            name="Test Key"
        )
        
        mock_api_key_manager.validate_api_key = AsyncMock(return_value=mock_payload)
        
        db_session = AsyncMock()
        
        context = await auth_service.extract_tenant_context_from_api_key(
            db=db_session,
            tenant_id="tenant_abc",
            key="abc12345_secretkey"
        )
        
        assert isinstance(context, TenantContext)
        assert context.tenant_id == "tenant_abc"
        assert context.user_id == "api_key"
        assert context.role == "developer"
        assert context.auth_method == "api_key"
        assert context.api_key_id == key_id
    
    @pytest.mark.asyncio
    async def test_verify_user_credentials_success(self, auth_service):
        """Test successful user credential verification"""
        # Create a test user with hashed password
        password = "test_password_123"
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        user = User(
            id=uuid4(),
            email="test@example.com",
            password_hash=password_hash.decode('utf-8'),
            role="admin",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        # Mock database session
        db_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = user
        db_session.execute = AsyncMock(return_value=mock_result)
        
        # Verify credentials
        result = await auth_service.verify_user_credentials(
            db=db_session,
            email="test@example.com",
            password=password
        )
        
        assert result is not None
        assert result.email == "test@example.com"
        assert result.role == "admin"
    
    @pytest.mark.asyncio
    async def test_verify_user_credentials_user_not_found(self, auth_service):
        """Test credential verification with non-existent user"""
        # Mock database session
        db_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        db_session.execute = AsyncMock(return_value=mock_result)
        
        # Verify credentials
        result = await auth_service.verify_user_credentials(
            db=db_session,
            email="nonexistent@example.com",
            password="password"
        )
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_verify_user_credentials_invalid_password(self, auth_service):
        """Test credential verification with invalid password"""
        # Create a test user with hashed password
        password = "correct_password"
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        user = User(
            id=uuid4(),
            email="test@example.com",
            password_hash=password_hash.decode('utf-8'),
            role="admin",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        # Mock database session
        db_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = user
        db_session.execute = AsyncMock(return_value=mock_result)
        
        # Verify credentials with wrong password
        result = await auth_service.verify_user_credentials(
            db=db_session,
            email="test@example.com",
            password="wrong_password"
        )
        
        assert result is None
    
    def test_extract_tenant_context_with_jwt(self, auth_service, mock_jwt_handler):
        """Test extract_tenant_context convenience method with JWT"""
        mock_payload = TokenPayload(
            tenant_id="tenant_abc",
            user_id="user_123",
            role="admin",
            exp=int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
            iat=int(datetime.utcnow().timestamp())
        )
        mock_jwt_handler.validate_jwt.return_value = mock_payload
        
        context = auth_service.extract_tenant_context(token="test_token")
        
        assert context is not None
        assert context.tenant_id == "tenant_abc"
        assert context.auth_method == "jwt"
    
    def test_extract_tenant_context_with_invalid_jwt(self, auth_service, mock_jwt_handler):
        """Test extract_tenant_context with invalid JWT"""
        mock_jwt_handler.validate_jwt.side_effect = AuthenticationError(
            "INVALID_TOKEN",
            "Token is invalid"
        )
        
        context = auth_service.extract_tenant_context(token="invalid_token")
        
        assert context is None
    
    def test_extract_tenant_context_without_credentials(self, auth_service):
        """Test extract_tenant_context without any credentials"""
        context = auth_service.extract_tenant_context()
        
        assert context is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
