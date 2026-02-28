"""
Unit Tests for RBAC Policy Engine

Tests the RBAC engine's permission evaluation logic, default roles,
and tenant-specific policy loading.

Requirements: 3.1, 3.2, 3.3, 3.4
"""

import pytest
from uuid import uuid4
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.rbac import (
    RBACEngine,
    Permission,
    RoleDefinition,
    DEFAULT_ROLES
)
from app.models.tenant import RBACPolicy


class TestPermission:
    """Test Permission class"""
    
    def test_permission_creation(self):
        """Test creating a permission"""
        perm = Permission(action="read", resource="users")
        
        assert perm.action == "read"
        assert perm.resource == "users"
        assert perm.conditions == {}
    
    def test_permission_with_conditions(self):
        """Test creating a permission with conditions"""
        perm = Permission(
            action="update",
            resource="resources",
            conditions={"owner": True}
        )
        
        assert perm.action == "update"
        assert perm.resource == "resources"
        assert perm.conditions == {"owner": True}
    
    def test_permission_from_string(self):
        """Test creating permission from string"""
        perm = Permission.from_string("read:users")
        
        assert perm.action == "read"
        assert perm.resource == "users"
    
    def test_permission_from_string_invalid(self):
        """Test invalid permission string raises error"""
        with pytest.raises(ValueError, match="Invalid permission format"):
            Permission.from_string("invalid")
    
    def test_permission_matches_exact(self):
        """Test exact permission matching"""
        perm = Permission(action="read", resource="users")
        
        assert perm.matches("read", "users") is True
        assert perm.matches("write", "users") is False
        assert perm.matches("read", "resources") is False
    
    def test_permission_matches_wildcard_action(self):
        """Test wildcard action matching"""
        perm = Permission(action="*", resource="users")
        
        assert perm.matches("read", "users") is True
        assert perm.matches("write", "users") is True
        assert perm.matches("delete", "users") is True
        assert perm.matches("read", "resources") is False
    
    def test_permission_matches_wildcard_resource(self):
        """Test wildcard resource matching"""
        perm = Permission(action="read", resource="*")
        
        assert perm.matches("read", "users") is True
        assert perm.matches("read", "resources") is True
        assert perm.matches("read", "api_keys") is True
        assert perm.matches("write", "users") is False
    
    def test_permission_matches_wildcard_both(self):
        """Test wildcard matching for both action and resource"""
        perm = Permission(action="*", resource="*")
        
        assert perm.matches("read", "users") is True
        assert perm.matches("write", "resources") is True
        assert perm.matches("delete", "api_keys") is True


class TestRoleDefinition:
    """Test RoleDefinition class"""
    
    def test_role_definition_creation(self):
        """Test creating a role definition"""
        permissions = [
            Permission(action="read", resource="*"),
            Permission(action="create", resource="resources")
        ]
        role = RoleDefinition(name="developer", permissions=permissions)
        
        assert role.name == "developer"
        assert len(role.permissions) == 2
    
    def test_role_definition_from_strings(self):
        """Test creating role from permission strings"""
        role = RoleDefinition.from_permission_strings(
            name="developer",
            permission_strings=["read:*", "create:resources"]
        )
        
        assert role.name == "developer"
        assert len(role.permissions) == 2
    
    def test_role_has_permission_granted(self):
        """Test role has permission when granted"""
        role = RoleDefinition.from_permission_strings(
            name="developer",
            permission_strings=["read:*", "create:resources"]
        )
        
        assert role.has_permission("read", "users") is True
        assert role.has_permission("read", "resources") is True
        assert role.has_permission("create", "resources") is True
    
    def test_role_has_permission_denied(self):
        """Test role doesn't have permission when not granted"""
        role = RoleDefinition.from_permission_strings(
            name="read_only",
            permission_strings=["read:*"]
        )
        
        assert role.has_permission("create", "resources") is False
        assert role.has_permission("delete", "users") is False
        assert role.has_permission("update", "api_keys") is False


class TestRBACEngine:
    """Test RBACEngine class"""
    
    def test_engine_initialization(self):
        """Test RBAC engine initializes with default roles"""
        engine = RBACEngine()
        
        # Should have default roles loaded
        assert len(engine._default_roles) == 3
        assert "admin" in engine._default_roles
        assert "developer" in engine._default_roles
        assert "read_only" in engine._default_roles
    
    def test_default_roles_structure(self):
        """Test default roles have expected structure"""
        assert "admin" in DEFAULT_ROLES
        assert "developer" in DEFAULT_ROLES
        assert "read_only" in DEFAULT_ROLES
        
        # Admin should have wildcard permission
        assert "*:*" in DEFAULT_ROLES["admin"]
        
        # Developer should have read and create permissions
        assert "read:*" in DEFAULT_ROLES["developer"]
        assert "create:resources" in DEFAULT_ROLES["developer"]
        
        # Read-only should only have read permission
        assert "read:*" in DEFAULT_ROLES["read_only"]
    
    def test_check_permission_admin_all_access(self):
        """Test admin role has access to everything"""
        engine = RBACEngine()
        
        # Admin should be able to do anything
        assert engine.check_permission("admin", "read", "users") is True
        assert engine.check_permission("admin", "create", "resources") is True
        assert engine.check_permission("admin", "update", "api_keys") is True
        assert engine.check_permission("admin", "delete", "jobs") is True
    
    def test_check_permission_developer_allowed(self):
        """Test developer role has expected permissions"""
        engine = RBACEngine()
        
        # Developer should be able to read anything
        assert engine.check_permission("developer", "read", "users") is True
        assert engine.check_permission("developer", "read", "resources") is True
        assert engine.check_permission("developer", "read", "jobs") is True
        
        # Developer should be able to create/update/delete resources
        assert engine.check_permission("developer", "create", "resources") is True
        assert engine.check_permission("developer", "update", "resources") is True
        assert engine.check_permission("developer", "delete", "resources") is True
        
        # Developer should be able to create jobs
        assert engine.check_permission("developer", "create", "jobs") is True
    
    def test_check_permission_developer_denied(self):
        """Test developer role is denied certain permissions"""
        engine = RBACEngine()
        
        # Developer should NOT be able to manage users
        assert engine.check_permission("developer", "create", "users") is False
        assert engine.check_permission("developer", "delete", "users") is False
        
        # Developer should NOT be able to manage API keys
        assert engine.check_permission("developer", "create", "api_keys") is False
        assert engine.check_permission("developer", "delete", "api_keys") is False
    
    def test_check_permission_read_only_allowed(self):
        """Test read_only role can only read"""
        engine = RBACEngine()
        
        # Read-only should be able to read anything
        assert engine.check_permission("read_only", "read", "users") is True
        assert engine.check_permission("read_only", "read", "resources") is True
        assert engine.check_permission("read_only", "read", "api_keys") is True
        assert engine.check_permission("read_only", "read", "jobs") is True
    
    def test_check_permission_read_only_denied(self):
        """Test read_only role cannot write"""
        engine = RBACEngine()
        
        # Read-only should NOT be able to create/update/delete anything
        assert engine.check_permission("read_only", "create", "resources") is False
        assert engine.check_permission("read_only", "update", "users") is False
        assert engine.check_permission("read_only", "delete", "api_keys") is False
        assert engine.check_permission("read_only", "create", "jobs") is False
    
    def test_check_permission_unknown_role(self):
        """Test unknown role is denied all permissions"""
        engine = RBACEngine()
        
        # Unknown role should be denied everything
        assert engine.check_permission("unknown_role", "read", "users") is False
        assert engine.check_permission("unknown_role", "create", "resources") is False
        assert engine.check_permission("unknown_role", "delete", "api_keys") is False
    
    def test_check_permission_with_tenant_policies(self):
        """Test permission check with tenant-specific policies"""
        engine = RBACEngine()
        
        # Create custom tenant policy
        custom_role = RoleDefinition.from_permission_strings(
            name="custom_role",
            permission_strings=["read:resources", "create:resources"]
        )
        tenant_policies = {"custom_role": custom_role}
        
        # Custom role should have specified permissions
        assert engine.check_permission(
            "custom_role", "read", "resources", tenant_policies
        ) is True
        assert engine.check_permission(
            "custom_role", "create", "resources", tenant_policies
        ) is True
        
        # Custom role should NOT have other permissions
        assert engine.check_permission(
            "custom_role", "delete", "resources", tenant_policies
        ) is False
        assert engine.check_permission(
            "custom_role", "read", "users", tenant_policies
        ) is False
    
    def test_check_permission_tenant_overrides_default(self):
        """Test tenant policies override default roles"""
        engine = RBACEngine()
        
        # Create tenant policy that overrides developer role
        custom_developer = RoleDefinition.from_permission_strings(
            name="developer",
            permission_strings=["read:*"]  # More restrictive than default
        )
        tenant_policies = {"developer": custom_developer}
        
        # Should use tenant policy (read-only)
        assert engine.check_permission(
            "developer", "read", "resources", tenant_policies
        ) is True
        assert engine.check_permission(
            "developer", "create", "resources", tenant_policies
        ) is False
    
    def test_get_role_permissions_default(self):
        """Test getting permissions for default role"""
        engine = RBACEngine()
        
        permissions = engine.get_role_permissions("developer")
        
        assert "read:*" in permissions
        assert "create:resources" in permissions
        assert "update:resources" in permissions
    
    def test_get_role_permissions_tenant(self):
        """Test getting permissions for tenant role"""
        engine = RBACEngine()
        
        custom_role = RoleDefinition.from_permission_strings(
            name="custom_role",
            permission_strings=["read:resources", "create:resources"]
        )
        tenant_policies = {"custom_role": custom_role}
        
        permissions = engine.get_role_permissions("custom_role", tenant_policies)
        
        assert "read:resources" in permissions
        assert "create:resources" in permissions
        assert len(permissions) == 2
    
    def test_get_role_permissions_unknown(self):
        """Test getting permissions for unknown role returns empty list"""
        engine = RBACEngine()
        
        permissions = engine.get_role_permissions("unknown_role")
        
        assert permissions == []
    
    def test_clear_cache_specific_tenant(self):
        """Test clearing cache for specific tenant"""
        engine = RBACEngine()
        
        # Add some cached policies
        engine._policy_cache["tenant_1"] = {}
        engine._policy_cache["tenant_2"] = {}
        
        # Clear specific tenant
        engine.clear_cache("tenant_1")
        
        assert "tenant_1" not in engine._policy_cache
        assert "tenant_2" in engine._policy_cache
    
    def test_clear_cache_all(self):
        """Test clearing all caches"""
        engine = RBACEngine()
        
        # Add some cached policies
        engine._policy_cache["tenant_1"] = {}
        engine._policy_cache["tenant_2"] = {}
        
        # Clear all
        engine.clear_cache()
        
        assert len(engine._policy_cache) == 0


@pytest.mark.asyncio
class TestRBACEngineDatabase:
    """Test RBAC engine database operations"""
    
    async def test_load_tenant_policies_empty(self, db_session: AsyncSession):
        """Test loading tenant policies when none exist"""
        engine = RBACEngine()
        
        policies = await engine.load_tenant_policies(db_session, "tenant_test")
        
        assert policies == {}
    
    async def test_load_tenant_policies_with_data(self, db_session: AsyncSession):
        """Test loading tenant policies from database"""
        engine = RBACEngine()
        
        # Create test RBAC policy
        policy = RBACPolicy(
            role="custom_role",
            permissions=[
                {"action": "read", "resource": "resources"},
                {"action": "create", "resource": "resources"}
            ]
        )
        db_session.add(policy)
        await db_session.commit()
        
        # Load policies
        policies = await engine.load_tenant_policies(db_session, "tenant_test")
        
        assert "custom_role" in policies
        assert policies["custom_role"].name == "custom_role"
        assert len(policies["custom_role"].permissions) == 2
    
    async def test_check_permission_with_db(self, db_session: AsyncSession):
        """Test permission check with database loading"""
        engine = RBACEngine()
        
        # Create test RBAC policy
        policy = RBACPolicy(
            role="custom_role",
            permissions=[
                {"action": "read", "resource": "resources"}
            ]
        )
        db_session.add(policy)
        await db_session.commit()
        
        # Check permission (should load from DB)
        allowed = await engine.check_permission_with_db(
            db=db_session,
            tenant_id="tenant_test",
            role="custom_role",
            action="read",
            resource="resources"
        )
        
        assert allowed is True
        
        # Check denied permission
        denied = await engine.check_permission_with_db(
            db=db_session,
            tenant_id="tenant_test",
            role="custom_role",
            action="delete",
            resource="resources"
        )
        
        assert denied is False
    
    async def test_check_permission_with_db_uses_cache(self, db_session: AsyncSession):
        """Test that permission check uses cache on subsequent calls"""
        engine = RBACEngine()
        
        # Create test RBAC policy
        policy = RBACPolicy(
            role="custom_role",
            permissions=[
                {"action": "read", "resource": "resources"}
            ]
        )
        db_session.add(policy)
        await db_session.commit()
        
        # First call - loads from DB
        await engine.check_permission_with_db(
            db=db_session,
            tenant_id="tenant_test",
            role="custom_role",
            action="read",
            resource="resources"
        )
        
        # Verify cache was populated
        assert "tenant_test" in engine._policy_cache
        
        # Second call - should use cache
        allowed = await engine.check_permission_with_db(
            db=db_session,
            tenant_id="tenant_test",
            role="custom_role",
            action="read",
            resource="resources"
        )
        
        assert allowed is True
