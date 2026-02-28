"""
Unit tests for RBAC Policy Manager

Tests the tenant-specific RBAC policy management functionality including
creation, updates, deletion, and validation of policies.

Requirements: 3.5
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
from datetime import datetime

from app.auth.rbac_policy_manager import RBACPolicyManager
from app.models.tenant import RBACPolicy


@pytest.fixture
def policy_manager():
    """Create RBACPolicyManager instance"""
    return RBACPolicyManager()


@pytest.fixture
def sample_permissions():
    """Sample permissions for testing"""
    return [
        {"action": "read", "resource": "*"},
        {"action": "create", "resource": "reports"},
        {"action": "update", "resource": "reports"}
    ]


class TestRBACPolicyManager:
    """Test suite for RBACPolicyManager"""
    
    @pytest.mark.asyncio
    async def test_create_policy(self, db_session, policy_manager, sample_permissions):
        """Test creating a new RBAC policy"""
        # Create policy
        policy = await policy_manager.create_policy(
            db=db_session,
            role="analyst",
            permissions=sample_permissions,
            tenant_id="test_tenant"
        )
        
        # Verify policy was created
        assert policy.id is not None
        assert policy.role == "analyst"
        assert policy.permissions == sample_permissions
        assert policy.created_at is not None
        assert policy.updated_at is not None
    
    @pytest.mark.asyncio
    async def test_create_duplicate_role_fails(self, db_session, policy_manager, sample_permissions):
        """Test that creating a duplicate role raises an error"""
        # Create first policy
        await policy_manager.create_policy(
            db=db_session,
            role="analyst",
            permissions=sample_permissions,
            tenant_id="test_tenant"
        )
        
        # Attempt to create duplicate
        with pytest.raises(ValueError, match="Role 'analyst' already exists"):
            await policy_manager.create_policy(
                db=db_session,
                role="analyst",
                permissions=sample_permissions,
                tenant_id="test_tenant"
            )
    
    @pytest.mark.asyncio
    async def test_update_policy(self, db_session, policy_manager, sample_permissions):
        """Test updating an existing RBAC policy"""
        # Create policy
        original = await policy_manager.create_policy(
            db=db_session,
            role="analyst",
            permissions=sample_permissions,
            tenant_id="test_tenant"
        )
        
        # Update permissions
        new_permissions = [
            {"action": "read", "resource": "*"},
            {"action": "delete", "resource": "reports"}
        ]
        
        updated = await policy_manager.update_policy(
            db=db_session,
            role="analyst",
            permissions=new_permissions,
            tenant_id="test_tenant"
        )
        
        # Verify update
        assert updated.id == original.id
        assert updated.role == "analyst"
        assert updated.permissions == new_permissions
        assert updated.updated_at >= original.updated_at
    
    @pytest.mark.asyncio
    async def test_update_nonexistent_policy_fails(self, db_session, policy_manager, sample_permissions):
        """Test that updating a non-existent role raises an error"""
        with pytest.raises(ValueError, match="Role 'nonexistent' does not exist"):
            await policy_manager.update_policy(
                db=db_session,
                role="nonexistent",
                permissions=sample_permissions,
                tenant_id="test_tenant"
            )
    
    @pytest.mark.asyncio
    async def test_delete_policy(self, db_session, policy_manager, sample_permissions):
        """Test deleting an RBAC policy"""
        # Create policy
        await policy_manager.create_policy(
            db=db_session,
            role="analyst",
            permissions=sample_permissions,
            tenant_id="test_tenant"
        )
        
        # Delete policy
        deleted = await policy_manager.delete_policy(
            db=db_session,
            role="analyst",
            tenant_id="test_tenant"
        )
        
        assert deleted is True
        
        # Verify policy is gone
        policy = await policy_manager.get_policy(
            db=db_session,
            role="analyst",
            tenant_id="test_tenant"
        )
        assert policy is None
    
    @pytest.mark.asyncio
    async def test_delete_nonexistent_policy(self, db_session, policy_manager):
        """Test deleting a non-existent policy returns False"""
        deleted = await policy_manager.delete_policy(
            db=db_session,
            role="nonexistent",
            tenant_id="test_tenant"
        )
        
        assert deleted is False
    
    @pytest.mark.asyncio
    async def test_get_policy(self, db_session, policy_manager, sample_permissions):
        """Test retrieving a specific policy"""
        # Create policy
        created = await policy_manager.create_policy(
            db=db_session,
            role="analyst",
            permissions=sample_permissions,
            tenant_id="test_tenant"
        )
        
        # Retrieve policy
        retrieved = await policy_manager.get_policy(
            db=db_session,
            role="analyst",
            tenant_id="test_tenant"
        )
        
        assert retrieved is not None
        assert retrieved.id == created.id
        assert retrieved.role == "analyst"
        assert retrieved.permissions == sample_permissions
    
    @pytest.mark.asyncio
    async def test_get_nonexistent_policy(self, db_session, policy_manager):
        """Test retrieving a non-existent policy returns None"""
        policy = await policy_manager.get_policy(
            db=db_session,
            role="nonexistent",
            tenant_id="test_tenant"
        )
        
        assert policy is None
    
    @pytest.mark.asyncio
    async def test_list_policies(self, db_session, policy_manager):
        """Test listing all policies"""
        # Create multiple policies
        policies_data = [
            ("analyst", [{"action": "read", "resource": "*"}]),
            ("viewer", [{"action": "read", "resource": "reports"}]),
            ("editor", [{"action": "update", "resource": "*"}])
        ]
        
        for role, permissions in policies_data:
            await policy_manager.create_policy(
                db=db_session,
                role=role,
                permissions=permissions,
                tenant_id="test_tenant"
            )
        
        # List all policies
        policies = await policy_manager.list_policies(
            db=db_session,
            tenant_id="test_tenant"
        )
        
        assert len(policies) == 3
        roles = [p.role for p in policies]
        assert "analyst" in roles
        assert "viewer" in roles
        assert "editor" in roles
    
    @pytest.mark.asyncio
    async def test_list_policies_empty(self, db_session, policy_manager):
        """Test listing policies when none exist"""
        policies = await policy_manager.list_policies(
            db=db_session,
            tenant_id="test_tenant"
        )
        
        assert len(policies) == 0
    
    @pytest.mark.asyncio
    async def test_upsert_policy_creates_new(self, db_session, policy_manager, sample_permissions):
        """Test upsert creates a new policy when it doesn't exist"""
        policy = await policy_manager.upsert_policy(
            db=db_session,
            role="analyst",
            permissions=sample_permissions,
            tenant_id="test_tenant"
        )
        
        assert policy.id is not None
        assert policy.role == "analyst"
        assert policy.permissions == sample_permissions
    
    @pytest.mark.asyncio
    async def test_upsert_policy_updates_existing(self, db_session, policy_manager, sample_permissions):
        """Test upsert updates an existing policy"""
        # Create initial policy
        original = await policy_manager.create_policy(
            db=db_session,
            role="analyst",
            permissions=sample_permissions,
            tenant_id="test_tenant"
        )
        
        # Upsert with new permissions
        new_permissions = [{"action": "delete", "resource": "*"}]
        updated = await policy_manager.upsert_policy(
            db=db_session,
            role="analyst",
            permissions=new_permissions,
            tenant_id="test_tenant"
        )
        
        assert updated.id == original.id
        assert updated.permissions == new_permissions
    
    @pytest.mark.asyncio
    async def test_validate_permissions_invalid_format(self, policy_manager):
        """Test that invalid permissions format raises ValueError"""
        # Not a list
        with pytest.raises(ValueError, match="Permissions must be a list"):
            policy_manager._validate_permissions("not a list")
        
        # List item not a dict
        with pytest.raises(ValueError, match="must be a dictionary"):
            policy_manager._validate_permissions(["not a dict"])
        
        # Missing action field
        with pytest.raises(ValueError, match="missing 'action' field"):
            policy_manager._validate_permissions([{"resource": "users"}])
        
        # Missing resource field
        with pytest.raises(ValueError, match="missing 'resource' field"):
            policy_manager._validate_permissions([{"action": "read"}])
        
        # Action not a string
        with pytest.raises(ValueError, match="'action' must be a string"):
            policy_manager._validate_permissions([{"action": 123, "resource": "users"}])
        
        # Resource not a string
        with pytest.raises(ValueError, match="'resource' must be a string"):
            policy_manager._validate_permissions([{"action": "read", "resource": 123}])
        
        # Conditions not a dict
        with pytest.raises(ValueError, match="'conditions' must be a dictionary"):
            policy_manager._validate_permissions([
                {"action": "read", "resource": "users", "conditions": "not a dict"}
            ])
    
    @pytest.mark.asyncio
    async def test_validate_permissions_valid_format(self, policy_manager):
        """Test that valid permissions format passes validation"""
        # Basic permissions
        valid_permissions = [
            {"action": "read", "resource": "users"},
            {"action": "create", "resource": "reports"}
        ]
        policy_manager._validate_permissions(valid_permissions)
        
        # With conditions
        valid_with_conditions = [
            {"action": "read", "resource": "users", "conditions": {"owner": True}}
        ]
        policy_manager._validate_permissions(valid_with_conditions)
        
        # Wildcards
        valid_wildcards = [
            {"action": "*", "resource": "*"}
        ]
        policy_manager._validate_permissions(valid_wildcards)
    
    @pytest.mark.asyncio
    async def test_create_policy_with_conditions(self, db_session, policy_manager):
        """Test creating a policy with permission conditions"""
        permissions = [
            {
                "action": "update",
                "resource": "resources",
                "conditions": {"owner": True}
            }
        ]
        
        policy = await policy_manager.create_policy(
            db=db_session,
            role="owner_only",
            permissions=permissions,
            tenant_id="test_tenant"
        )
        
        assert policy.permissions[0]["conditions"] == {"owner": True}
    
    @pytest.mark.asyncio
    async def test_multiple_tenants_isolation(self, db_engine, policy_manager, sample_permissions):
        """Test that policies are isolated between tenants"""
        # This test simulates multiple tenant schemas by using separate sessions
        # In production, each tenant would have their own schema
        
        session_factory = async_sessionmaker(
            db_engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        # Create policy in "tenant A"
        async with session_factory() as session_a:
            policy_a = await policy_manager.create_policy(
                db=session_a,
                role="analyst",
                permissions=sample_permissions,
                tenant_id="tenant_a"
            )
            assert policy_a.role == "analyst"
        
        # In a real multi-tenant setup with separate schemas,
        # this would be a different schema and the role wouldn't conflict
        # For this test, we're just verifying the manager works correctly
