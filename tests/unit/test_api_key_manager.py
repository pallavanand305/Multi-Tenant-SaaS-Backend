"""
Unit Tests for API Key Manager

Tests for API key generation, validation, and revocation functionality.
Validates secure key generation, bcrypt hashing, and database operations.

Requirements: 4.1, 4.2, 4.3, 4.4
"""

import pytest
import bcrypt
from datetime import datetime
from uuid import uuid4, UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.api_key_manager import APIKeyManager, APIKeyPayload, APIKeyError
from app.models.tenant import APIKey


@pytest.fixture
def api_key_manager():
    """Create APIKeyManager instance for testing"""
    return APIKeyManager(bcrypt_rounds=4)  # Use fewer rounds for faster tests


@pytest.fixture
async def tenant_db_session(db_session: AsyncSession):
    """
    Create a test tenant schema and return a session configured for it.
    
    This fixture sets up an isolated tenant schema for testing API key operations.
    """
    tenant_id = "test_tenant_123"
    schema_name = f"tenant_{tenant_id}"
    
    # Create tenant schema
    await db_session.execute(text(f"CREATE SCHEMA IF NOT EXISTS {schema_name}"))
    await db_session.commit()
    
    # Set search path to tenant schema
    await db_session.execute(text(f"SET search_path TO {schema_name}, public"))
    
    # Create api_keys table in tenant schema
    await db_session.execute(text(f"""
        CREATE TABLE IF NOT EXISTS {schema_name}.api_keys (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            key_prefix VARCHAR(16) NOT NULL,
            hashed_secret VARCHAR(255) NOT NULL,
            name VARCHAR(255) NOT NULL,
            role VARCHAR(32) NOT NULL,
            created_by UUID,
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            revoked_at TIMESTAMP,
            last_used_at TIMESTAMP
        )
    """))
    await db_session.commit()
    
    yield db_session, tenant_id
    
    # Cleanup: drop tenant schema
    await db_session.execute(text(f"DROP SCHEMA IF EXISTS {schema_name} CASCADE"))
    await db_session.commit()


class TestAPIKeyGeneration:
    """Test API key generation functionality"""
    
    @pytest.mark.unit
    async def test_generate_key_string_format(self, api_key_manager):
        """Test that generated keys have correct format"""
        full_key, prefix, secret = api_key_manager._generate_key_string()
        
        # Check format: prefix_secret
        assert '_' in full_key
        assert full_key == f"{prefix}_{secret}"
        
        # Check lengths
        assert len(prefix) == 8
        assert len(secret) == 32
        
        # Check that prefix and secret are URL-safe
        assert prefix.replace('-', '').replace('_', '').isalnum()
        assert secret.replace('-', '').replace('_', '').isalnum()
    
    @pytest.mark.unit
    async def test_generate_key_string_uniqueness(self, api_key_manager):
        """Test that generated keys are unique"""
        keys = set()
        
        for _ in range(100):
            full_key, _, _ = api_key_manager._generate_key_string()
            keys.add(full_key)
        
        # All keys should be unique
        assert len(keys) == 100
    
    @pytest.mark.unit
    async def test_hash_secret(self, api_key_manager):
        """Test that secrets are properly hashed with bcrypt"""
        secret = "test_secret_12345678901234567890"
        hashed = api_key_manager._hash_secret(secret)
        
        # Check that hash is bcrypt format
        assert hashed.startswith('$2b$')
        
        # Check that hash is different from secret
        assert hashed != secret
        
        # Check that hash can be verified
        assert bcrypt.checkpw(secret.encode('utf-8'), hashed.encode('utf-8'))
    
    @pytest.mark.unit
    async def test_hash_secret_different_each_time(self, api_key_manager):
        """Test that hashing the same secret produces different hashes (salt)"""
        secret = "test_secret_12345678901234567890"
        
        hash1 = api_key_manager._hash_secret(secret)
        hash2 = api_key_manager._hash_secret(secret)
        
        # Hashes should be different due to different salts
        assert hash1 != hash2
        
        # But both should verify correctly
        assert bcrypt.checkpw(secret.encode('utf-8'), hash1.encode('utf-8'))
        assert bcrypt.checkpw(secret.encode('utf-8'), hash2.encode('utf-8'))
    
    @pytest.mark.unit
    async def test_verify_secret_correct(self, api_key_manager):
        """Test secret verification with correct secret"""
        secret = "test_secret_12345678901234567890"
        hashed = api_key_manager._hash_secret(secret)
        
        assert api_key_manager._verify_secret(secret, hashed) is True
    
    @pytest.mark.unit
    async def test_verify_secret_incorrect(self, api_key_manager):
        """Test secret verification with incorrect secret"""
        secret = "test_secret_12345678901234567890"
        wrong_secret = "wrong_secret_12345678901234567890"
        hashed = api_key_manager._hash_secret(secret)
        
        assert api_key_manager._verify_secret(wrong_secret, hashed) is False
    
    @pytest.mark.unit
    @pytest.mark.requires_db
    async def test_create_api_key_success(self, api_key_manager, tenant_db_session):
        """Test successful API key creation"""
        db, tenant_id = tenant_db_session
        
        api_key, full_key = await api_key_manager.create_api_key(
            db=db,
            tenant_id=tenant_id,
            role="developer",
            name="Test API Key"
        )
        
        # Check API key model
        assert api_key.id is not None
        assert isinstance(api_key.id, UUID)
        assert api_key.key_prefix is not None
        assert len(api_key.key_prefix) == 8
        assert api_key.hashed_secret is not None
        assert api_key.name == "Test API Key"
        assert api_key.role == "developer"
        assert api_key.created_at is not None
        assert api_key.revoked_at is None
        assert api_key.last_used_at is None
        
        # Check full key format
        assert '_' in full_key
        prefix, secret = full_key.split('_', 1)
        assert prefix == api_key.key_prefix
        assert len(secret) == 32
        
        # Verify that secret can be verified against hash
        assert api_key_manager._verify_secret(secret, api_key.hashed_secret)
    
    @pytest.mark.unit
    @pytest.mark.requires_db
    async def test_create_api_key_with_created_by(self, api_key_manager, tenant_db_session):
        """Test API key creation with created_by user"""
        db, tenant_id = tenant_db_session
        user_id = uuid4()
        
        api_key, full_key = await api_key_manager.create_api_key(
            db=db,
            tenant_id=tenant_id,
            role="admin",
            name="Admin Key",
            created_by=user_id
        )
        
        assert api_key.created_by == user_id
    
    @pytest.mark.unit
    @pytest.mark.requires_db
    async def test_create_multiple_api_keys(self, api_key_manager, tenant_db_session):
        """Test creating multiple API keys for same tenant"""
        db, tenant_id = tenant_db_session
        
        keys = []
        for i in range(5):
            api_key, full_key = await api_key_manager.create_api_key(
                db=db,
                tenant_id=tenant_id,
                role="developer",
                name=f"Key {i}"
            )
            keys.append((api_key, full_key))
        
        # All keys should have unique IDs and prefixes
        ids = [k[0].id for k in keys]
        prefixes = [k[0].key_prefix for k in keys]
        full_keys = [k[1] for k in keys]
        
        assert len(set(ids)) == 5
        assert len(set(prefixes)) == 5
        assert len(set(full_keys)) == 5


class TestAPIKeyValidation:
    """Test API key validation functionality"""
    
    @pytest.mark.unit
    @pytest.mark.requires_db
    async def test_validate_api_key_success(self, api_key_manager, tenant_db_session):
        """Test successful API key validation"""
        db, tenant_id = tenant_db_session
        
        # Create API key
        api_key, full_key = await api_key_manager.create_api_key(
            db=db,
            tenant_id=tenant_id,
            role="developer",
            name="Test Key"
        )
        
        # Validate API key
        payload = await api_key_manager.validate_api_key(
            db=db,
            tenant_id=tenant_id,
            key=full_key
        )
        
        # Check payload
        assert isinstance(payload, APIKeyPayload)
        assert payload.key_id == api_key.id
        assert payload.tenant_id == tenant_id
        assert payload.role == "developer"
        assert payload.name == "Test Key"
        
        # Check that last_used_at was updated
        await db.refresh(api_key)
        assert api_key.last_used_at is not None
    
    @pytest.mark.unit
    @pytest.mark.requires_db
    async def test_validate_api_key_invalid_format(self, api_key_manager, tenant_db_session):
        """Test validation with invalid key format"""
        db, tenant_id = tenant_db_session
        
        # Key without underscore
        with pytest.raises(APIKeyError) as exc_info:
            await api_key_manager.validate_api_key(
                db=db,
                tenant_id=tenant_id,
                key="invalidkeyformat"
            )
        
        assert exc_info.value.code == "INVALID_API_KEY"
        assert "format is invalid" in exc_info.value.message
    
    @pytest.mark.unit
    @pytest.mark.requires_db
    async def test_validate_api_key_not_found(self, api_key_manager, tenant_db_session):
        """Test validation with non-existent key"""
        db, tenant_id = tenant_db_session
        
        # Key with valid format but doesn't exist
        with pytest.raises(APIKeyError) as exc_info:
            await api_key_manager.validate_api_key(
                db=db,
                tenant_id=tenant_id,
                key="abcd1234_12345678901234567890123456789012"
            )
        
        assert exc_info.value.code == "INVALID_API_KEY"
        assert "not found or has been revoked" in exc_info.value.message
    
    @pytest.mark.unit
    @pytest.mark.requires_db
    async def test_validate_api_key_wrong_secret(self, api_key_manager, tenant_db_session):
        """Test validation with correct prefix but wrong secret"""
        db, tenant_id = tenant_db_session
        
        # Create API key
        api_key, full_key = await api_key_manager.create_api_key(
            db=db,
            tenant_id=tenant_id,
            role="developer",
            name="Test Key"
        )
        
        # Use correct prefix but wrong secret
        prefix = full_key.split('_')[0]
        wrong_key = f"{prefix}_wrongsecret12345678901234567890"
        
        with pytest.raises(APIKeyError) as exc_info:
            await api_key_manager.validate_api_key(
                db=db,
                tenant_id=tenant_id,
                key=wrong_key
            )
        
        assert exc_info.value.code == "INVALID_API_KEY"
        assert "verification failed" in exc_info.value.message
    
    @pytest.mark.unit
    @pytest.mark.requires_db
    async def test_validate_revoked_api_key(self, api_key_manager, tenant_db_session):
        """Test that revoked keys cannot be validated"""
        db, tenant_id = tenant_db_session
        
        # Create and revoke API key
        api_key, full_key = await api_key_manager.create_api_key(
            db=db,
            tenant_id=tenant_id,
            role="developer",
            name="Test Key"
        )
        
        await api_key_manager.revoke_api_key(
            db=db,
            tenant_id=tenant_id,
            key_id=api_key.id
        )
        
        # Try to validate revoked key
        with pytest.raises(APIKeyError) as exc_info:
            await api_key_manager.validate_api_key(
                db=db,
                tenant_id=tenant_id,
                key=full_key
            )
        
        assert exc_info.value.code == "INVALID_API_KEY"
        assert "not found or has been revoked" in exc_info.value.message
    
    @pytest.mark.unit
    @pytest.mark.requires_db
    async def test_validate_updates_last_used_at(self, api_key_manager, tenant_db_session):
        """Test that validation updates last_used_at timestamp"""
        db, tenant_id = tenant_db_session
        
        # Create API key
        api_key, full_key = await api_key_manager.create_api_key(
            db=db,
            tenant_id=tenant_id,
            role="developer",
            name="Test Key"
        )
        
        # Initially last_used_at should be None
        assert api_key.last_used_at is None
        
        # Validate key
        await api_key_manager.validate_api_key(
            db=db,
            tenant_id=tenant_id,
            key=full_key
        )
        
        # Check that last_used_at was updated
        await db.refresh(api_key)
        assert api_key.last_used_at is not None
        assert isinstance(api_key.last_used_at, datetime)


class TestAPIKeyRevocation:
    """Test API key revocation functionality"""
    
    @pytest.mark.unit
    @pytest.mark.requires_db
    async def test_revoke_api_key_success(self, api_key_manager, tenant_db_session):
        """Test successful API key revocation"""
        db, tenant_id = tenant_db_session
        
        # Create API key
        api_key, full_key = await api_key_manager.create_api_key(
            db=db,
            tenant_id=tenant_id,
            role="developer",
            name="Test Key"
        )
        
        # Revoke key
        result = await api_key_manager.revoke_api_key(
            db=db,
            tenant_id=tenant_id,
            key_id=api_key.id
        )
        
        assert result is True
        
        # Check that revoked_at was set
        await db.refresh(api_key)
        assert api_key.revoked_at is not None
        assert isinstance(api_key.revoked_at, datetime)
    
    @pytest.mark.unit
    @pytest.mark.requires_db
    async def test_revoke_api_key_not_found(self, api_key_manager, tenant_db_session):
        """Test revoking non-existent API key"""
        db, tenant_id = tenant_db_session
        
        # Try to revoke non-existent key
        result = await api_key_manager.revoke_api_key(
            db=db,
            tenant_id=tenant_id,
            key_id=uuid4()
        )
        
        assert result is False
    
    @pytest.mark.unit
    @pytest.mark.requires_db
    async def test_revoke_already_revoked_key(self, api_key_manager, tenant_db_session):
        """Test revoking an already revoked key"""
        db, tenant_id = tenant_db_session
        
        # Create and revoke API key
        api_key, full_key = await api_key_manager.create_api_key(
            db=db,
            tenant_id=tenant_id,
            role="developer",
            name="Test Key"
        )
        
        # First revocation
        result1 = await api_key_manager.revoke_api_key(
            db=db,
            tenant_id=tenant_id,
            key_id=api_key.id
        )
        assert result1 is True
        
        # Second revocation should return False (already revoked)
        result2 = await api_key_manager.revoke_api_key(
            db=db,
            tenant_id=tenant_id,
            key_id=api_key.id
        )
        assert result2 is False
    
    @pytest.mark.unit
    @pytest.mark.requires_db
    async def test_revoked_key_cannot_be_validated(self, api_key_manager, tenant_db_session):
        """Test that revoked keys fail validation"""
        db, tenant_id = tenant_db_session
        
        # Create API key
        api_key, full_key = await api_key_manager.create_api_key(
            db=db,
            tenant_id=tenant_id,
            role="developer",
            name="Test Key"
        )
        
        # Validate before revocation (should succeed)
        payload = await api_key_manager.validate_api_key(
            db=db,
            tenant_id=tenant_id,
            key=full_key
        )
        assert payload.key_id == api_key.id
        
        # Revoke key
        await api_key_manager.revoke_api_key(
            db=db,
            tenant_id=tenant_id,
            key_id=api_key.id
        )
        
        # Validate after revocation (should fail)
        with pytest.raises(APIKeyError) as exc_info:
            await api_key_manager.validate_api_key(
                db=db,
                tenant_id=tenant_id,
                key=full_key
            )
        
        assert exc_info.value.code == "INVALID_API_KEY"


class TestAPIKeyPayload:
    """Test APIKeyPayload class"""
    
    @pytest.mark.unit
    def test_api_key_payload_creation(self):
        """Test creating APIKeyPayload"""
        key_id = uuid4()
        payload = APIKeyPayload(
            key_id=key_id,
            tenant_id="tenant_123",
            role="developer",
            name="Test Key"
        )
        
        assert payload.key_id == key_id
        assert payload.tenant_id == "tenant_123"
        assert payload.role == "developer"
        assert payload.name == "Test Key"
    
    @pytest.mark.unit
    def test_api_key_payload_to_dict(self):
        """Test converting APIKeyPayload to dictionary"""
        key_id = uuid4()
        payload = APIKeyPayload(
            key_id=key_id,
            tenant_id="tenant_123",
            role="developer",
            name="Test Key"
        )
        
        payload_dict = payload.to_dict()
        
        assert payload_dict["key_id"] == str(key_id)
        assert payload_dict["tenant_id"] == "tenant_123"
        assert payload_dict["role"] == "developer"
        assert payload_dict["name"] == "Test Key"


class TestAPIKeyError:
    """Test APIKeyError exception"""
    
    @pytest.mark.unit
    def test_api_key_error_creation(self):
        """Test creating APIKeyError"""
        error = APIKeyError("INVALID_API_KEY", "API key is invalid")
        
        assert error.code == "INVALID_API_KEY"
        assert error.message == "API key is invalid"
        assert str(error) == "API key is invalid"
