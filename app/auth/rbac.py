"""
RBAC Policy Engine

Role-Based Access Control (RBAC) engine for evaluating permissions based on
user roles. Supports default roles (admin, developer, read_only) and custom
tenant-specific policies.

Requirements: 3.1, 3.2, 3.3, 3.4
"""

from typing import Optional, Dict, List
import structlog

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.tenant import RBACPolicy


logger = structlog.get_logger(__name__)


# Default role definitions
# Format: role -> list of permission strings (action:resource)
DEFAULT_ROLES = {
    "admin": [
        "*:*"  # All actions on all resources
    ],
    "developer": [
        "read:*",           # Read all resources
        "create:resources", # Create resources
        "update:resources", # Update resources
        "delete:resources", # Delete resources
        "read:jobs",        # Read background jobs
        "create:jobs",      # Create background jobs
        "read:usage",       # Read usage metrics
    ],
    "read_only": [
        "read:*"  # Read-only access to all resources
    ]
}


class Permission:
    """
    Represents a single permission.
    
    A permission consists of an action (e.g., create, read, update, delete)
    and a resource (e.g., users, api_keys, resources, jobs).
    """
    
    def __init__(self, action: str, resource: str, conditions: Optional[Dict] = None):
        """
        Initialize a permission.
        
        Args:
            action: Action to perform (create, read, update, delete, or *)
            resource: Resource type (users, api_keys, resources, jobs, or *)
            conditions: Optional conditions for the permission (e.g., {"owner": True})
        """
        self.action = action
        self.resource = resource
        self.conditions = conditions or {}
    
    def matches(self, required_action: str, required_resource: str) -> bool:
        """
        Check if this permission matches the required action and resource.
        
        Supports wildcard matching:
        - "*:*" matches any action on any resource
        - "read:*" matches read action on any resource
        - "*:users" matches any action on users resource
        
        Args:
            required_action: The action being checked
            required_resource: The resource being accessed
        
        Returns:
            True if permission matches, False otherwise
        """
        action_match = self.action == "*" or self.action == required_action
        resource_match = self.resource == "*" or self.resource == required_resource
        
        return action_match and resource_match
    
    @classmethod
    def from_string(cls, permission_str: str) -> "Permission":
        """
        Create a Permission from a string format "action:resource".
        
        Args:
            permission_str: Permission string (e.g., "read:users", "create:*")
        
        Returns:
            Permission object
        
        Raises:
            ValueError: If permission string format is invalid
        """
        if ":" not in permission_str:
            raise ValueError(f"Invalid permission format: {permission_str}. Expected 'action:resource'")
        
        action, resource = permission_str.split(":", 1)
        return cls(action=action, resource=resource)
    
    def __repr__(self) -> str:
        return f"<Permission(action={self.action}, resource={self.resource})>"
    
    def __str__(self) -> str:
        return f"{self.action}:{self.resource}"


class RoleDefinition:
    """
    Represents a role with its associated permissions.
    """
    
    def __init__(self, name: str, permissions: List[Permission]):
        """
        Initialize a role definition.
        
        Args:
            name: Role name (e.g., admin, developer, read_only)
            permissions: List of Permission objects
        """
        self.name = name
        self.permissions = permissions
    
    def has_permission(self, action: str, resource: str) -> bool:
        """
        Check if this role has permission for the given action and resource.
        
        Args:
            action: Action to check (e.g., read, create, update, delete)
            resource: Resource to check (e.g., users, api_keys, resources)
        
        Returns:
            True if role has permission, False otherwise
        """
        for permission in self.permissions:
            if permission.matches(action, resource):
                return True
        return False
    
    @classmethod
    def from_permission_strings(cls, name: str, permission_strings: List[str]) -> "RoleDefinition":
        """
        Create a RoleDefinition from a list of permission strings.
        
        Args:
            name: Role name
            permission_strings: List of permission strings (e.g., ["read:*", "create:resources"])
        
        Returns:
            RoleDefinition object
        """
        permissions = [Permission.from_string(perm_str) for perm_str in permission_strings]
        return cls(name=name, permissions=permissions)
    
    def __repr__(self) -> str:
        return f"<RoleDefinition(name={self.name}, permissions={len(self.permissions)})>"


class RBACEngine:
    """
    RBAC Policy Engine for permission evaluation.
    
    Evaluates whether a user with a specific role has permission to perform
    an action on a resource. Supports default roles and custom tenant-specific
    policies loaded from the database.
    
    Requirements:
    - 3.1: Evaluate RBAC policy for user's role
    - 3.2: Support admin, developer, and read-only roles
    - 3.3: Verify user's role permits requested action
    - 3.4: Reject requests when role doesn't permit action
    """
    
    def __init__(self):
        """Initialize RBAC engine with default roles."""
        self._default_roles = self._load_default_roles()
        self._policy_cache: Dict[str, Dict[str, RoleDefinition]] = {}
        
        logger.info(
            "RBACEngine initialized",
            default_roles=list(self._default_roles.keys())
        )
    
    def _load_default_roles(self) -> Dict[str, RoleDefinition]:
        """
        Load default role definitions.
        
        Returns:
            Dictionary mapping role names to RoleDefinition objects
        """
        roles = {}
        for role_name, permission_strings in DEFAULT_ROLES.items():
            roles[role_name] = RoleDefinition.from_permission_strings(
                name=role_name,
                permission_strings=permission_strings
            )
        return roles
    
    def check_permission(
        self,
        role: str,
        action: str,
        resource: str,
        tenant_policies: Optional[Dict[str, RoleDefinition]] = None
    ) -> bool:
        """
        Check if a role has permission to perform an action on a resource.
        
        First checks tenant-specific policies if provided, then falls back
        to default roles. This allows tenants to customize their RBAC policies
        while maintaining sensible defaults.
        
        Args:
            role: User's role (e.g., admin, developer, read_only)
            action: Action to perform (e.g., create, read, update, delete)
            resource: Resource type (e.g., users, api_keys, resources, jobs)
            tenant_policies: Optional tenant-specific role definitions
        
        Returns:
            True if role has permission, False otherwise
        
        Requirements: 3.1, 3.3, 3.4
        
        Example:
            engine = RBACEngine()
            
            # Check if developer can read resources
            allowed = engine.check_permission("developer", "read", "resources")
            # Returns: True
            
            # Check if read_only can delete resources
            allowed = engine.check_permission("read_only", "delete", "resources")
            # Returns: False
            
            # Check if admin can do anything
            allowed = engine.check_permission("admin", "delete", "users")
            # Returns: True
        """
        # Check tenant-specific policies first
        if tenant_policies and role in tenant_policies:
            role_def = tenant_policies[role]
            has_perm = role_def.has_permission(action, resource)
            
            logger.debug(
                "Permission check (tenant policy)",
                role=role,
                action=action,
                resource=resource,
                allowed=has_perm
            )
            
            return has_perm
        
        # Fall back to default roles
        if role in self._default_roles:
            role_def = self._default_roles[role]
            has_perm = role_def.has_permission(action, resource)
            
            logger.debug(
                "Permission check (default policy)",
                role=role,
                action=action,
                resource=resource,
                allowed=has_perm
            )
            
            return has_perm
        
        # Unknown role - deny by default
        logger.warning(
            "Permission denied - unknown role",
            role=role,
            action=action,
            resource=resource
        )
        
        return False
    
    async def load_tenant_policies(
        self,
        db: AsyncSession,
        tenant_id: str
    ) -> Dict[str, RoleDefinition]:
        """
        Load tenant-specific RBAC policies from database.
        
        Queries the RBACPolicy table in the tenant's schema and converts
        the stored policies into RoleDefinition objects.
        
        Args:
            db: Database session (must be set to tenant schema)
            tenant_id: Tenant identifier (for logging/caching)
        
        Returns:
            Dictionary mapping role names to RoleDefinition objects
        
        Requirements: 3.5
        
        Example:
            policies = await engine.load_tenant_policies(db, "tenant_abc")
            allowed = engine.check_permission(
                "custom_role",
                "read",
                "resources",
                tenant_policies=policies
            )
        """
        try:
            # Query all RBAC policies for the tenant
            stmt = select(RBACPolicy)
            result = await db.execute(stmt)
            policies = result.scalars().all()
            
            # Convert to RoleDefinition objects
            tenant_policies = {}
            for policy in policies:
                permissions = []
                
                # Parse permissions from JSONB field
                # Expected format: [{"action": "read", "resource": "users", "conditions": {...}}, ...]
                for perm_dict in policy.permissions:
                    permission = Permission(
                        action=perm_dict.get("action", "*"),
                        resource=perm_dict.get("resource", "*"),
                        conditions=perm_dict.get("conditions", {})
                    )
                    permissions.append(permission)
                
                tenant_policies[policy.role] = RoleDefinition(
                    name=policy.role,
                    permissions=permissions
                )
            
            logger.info(
                "Loaded tenant RBAC policies",
                tenant_id=tenant_id,
                roles=list(tenant_policies.keys())
            )
            
            # Cache the policies
            self._policy_cache[tenant_id] = tenant_policies
            
            return tenant_policies
            
        except Exception as e:
            logger.error(
                "Failed to load tenant RBAC policies",
                tenant_id=tenant_id,
                error=str(e)
            )
            # Return empty dict on error - will fall back to default roles
            return {}
    
    async def check_permission_with_db(
        self,
        db: AsyncSession,
        tenant_id: str,
        role: str,
        action: str,
        resource: str
    ) -> bool:
        """
        Check permission with automatic tenant policy loading.
        
        Convenience method that loads tenant policies from database
        and performs permission check in one call.
        
        Args:
            db: Database session (must be set to tenant schema)
            tenant_id: Tenant identifier
            role: User's role
            action: Action to perform
            resource: Resource type
        
        Returns:
            True if role has permission, False otherwise
        
        Requirements: 3.1, 3.3, 3.4, 3.5
        
        Example:
            allowed = await engine.check_permission_with_db(
                db=session,
                tenant_id="tenant_abc",
                role="developer",
                action="create",
                resource="resources"
            )
        """
        # Check cache first
        tenant_policies = self._policy_cache.get(tenant_id)
        
        # Load from database if not cached
        if tenant_policies is None:
            tenant_policies = await self.load_tenant_policies(db, tenant_id)
        
        return self.check_permission(role, action, resource, tenant_policies)
    
    def get_role_permissions(
        self,
        role: str,
        tenant_policies: Optional[Dict[str, RoleDefinition]] = None
    ) -> List[str]:
        """
        Get all permissions for a role.
        
        Returns a list of permission strings (action:resource) for the given role.
        Useful for debugging and displaying role capabilities.
        
        Args:
            role: Role name
            tenant_policies: Optional tenant-specific policies
        
        Returns:
            List of permission strings
        
        Example:
            permissions = engine.get_role_permissions("developer")
            # Returns: ["read:*", "create:resources", "update:resources", ...]
        """
        # Check tenant policies first
        if tenant_policies and role in tenant_policies:
            role_def = tenant_policies[role]
            return [str(perm) for perm in role_def.permissions]
        
        # Fall back to default roles
        if role in self._default_roles:
            role_def = self._default_roles[role]
            return [str(perm) for perm in role_def.permissions]
        
        return []
    
    def clear_cache(self, tenant_id: Optional[str] = None):
        """
        Clear the policy cache.
        
        Args:
            tenant_id: Optional tenant ID to clear specific cache, or None to clear all
        
        Example:
            # Clear specific tenant cache
            engine.clear_cache("tenant_abc")
            
            # Clear all caches
            engine.clear_cache()
        """
        if tenant_id:
            self._policy_cache.pop(tenant_id, None)
            logger.info("Cleared RBAC policy cache", tenant_id=tenant_id)
        else:
            self._policy_cache.clear()
            logger.info("Cleared all RBAC policy caches")
    
    async def create_tenant_policy(
        self,
        db: AsyncSession,
        tenant_id: str,
        role: str,
        permissions: List[Dict[str, any]]
    ) -> RBACPolicy:
        """
        Create a new RBAC policy for a tenant.
        
        Convenience method that creates a policy and clears the cache
        for the tenant to ensure the new policy is loaded on next access.
        
        Args:
            db: Database session (must be set to tenant schema)
            tenant_id: Tenant identifier
            role: Role name
            permissions: List of permission dictionaries
        
        Returns:
            RBACPolicy: Created policy object
        
        Requirements: 3.5
        
        Example:
            engine = RBACEngine()
            policy = await engine.create_tenant_policy(
                db=session,
                tenant_id="tenant_abc",
                role="analyst",
                permissions=[
                    {"action": "read", "resource": "*"},
                    {"action": "create", "resource": "reports"}
                ]
            )
        """
        from app.auth.rbac_policy_manager import RBACPolicyManager
        
        manager = RBACPolicyManager()
        policy = await manager.create_policy(db, role, permissions, tenant_id)
        
        # Clear cache to force reload on next access
        self.clear_cache(tenant_id)
        
        return policy
    
    async def update_tenant_policy(
        self,
        db: AsyncSession,
        tenant_id: str,
        role: str,
        permissions: List[Dict[str, any]]
    ) -> RBACPolicy:
        """
        Update an existing RBAC policy for a tenant.
        
        Convenience method that updates a policy and clears the cache
        for the tenant to ensure the updated policy is loaded on next access.
        
        Args:
            db: Database session (must be set to tenant schema)
            tenant_id: Tenant identifier
            role: Role name
            permissions: New list of permission dictionaries
        
        Returns:
            RBACPolicy: Updated policy object
        
        Requirements: 3.5
        
        Example:
            engine = RBACEngine()
            policy = await engine.update_tenant_policy(
                db=session,
                tenant_id="tenant_abc",
                role="analyst",
                permissions=[
                    {"action": "read", "resource": "*"},
                    {"action": "create", "resource": "reports"},
                    {"action": "update", "resource": "reports"}
                ]
            )
        """
        from app.auth.rbac_policy_manager import RBACPolicyManager
        
        manager = RBACPolicyManager()
        policy = await manager.update_policy(db, role, permissions, tenant_id)
        
        # Clear cache to force reload on next access
        self.clear_cache(tenant_id)
        
        return policy
    
    async def delete_tenant_policy(
        self,
        db: AsyncSession,
        tenant_id: str,
        role: str
    ) -> bool:
        """
        Delete an RBAC policy for a tenant.
        
        Convenience method that deletes a policy and clears the cache
        for the tenant.
        
        Args:
            db: Database session (must be set to tenant schema)
            tenant_id: Tenant identifier
            role: Role name to delete
        
        Returns:
            bool: True if policy was deleted, False if not found
        
        Requirements: 3.5
        
        Example:
            engine = RBACEngine()
            deleted = await engine.delete_tenant_policy(
                db=session,
                tenant_id="tenant_abc",
                role="old_role"
            )
        """
        from app.auth.rbac_policy_manager import RBACPolicyManager
        
        manager = RBACPolicyManager()
        deleted = await manager.delete_policy(db, role, tenant_id)
        
        # Clear cache to force reload on next access
        self.clear_cache(tenant_id)
        
        return deleted

    async def create_tenant_policy(
        self,
        db: AsyncSession,
        tenant_id: str,
        role: str,
        permissions: List[Dict[str, any]]
    ) -> RBACPolicy:
        """
        Create a new RBAC policy for a tenant.

        Convenience method that creates a policy and clears the cache
        for the tenant to ensure the new policy is loaded on next access.

        Args:
            db: Database session (must be set to tenant schema)
            tenant_id: Tenant identifier
            role: Role name
            permissions: List of permission dictionaries

        Returns:
            RBACPolicy: Created policy object

        Requirements: 3.5

        Example:
            engine = RBACEngine()
            policy = await engine.create_tenant_policy(
                db=session,
                tenant_id="tenant_abc",
                role="analyst",
                permissions=[
                    {"action": "read", "resource": "*"},
                    {"action": "create", "resource": "reports"}
                ]
            )
        """
        from app.auth.rbac_policy_manager import RBACPolicyManager

        manager = RBACPolicyManager()
        policy = await manager.create_policy(db, role, permissions, tenant_id)

        # Clear cache to force reload on next access
        self.clear_cache(tenant_id)

        return policy

    async def update_tenant_policy(
        self,
        db: AsyncSession,
        tenant_id: str,
        role: str,
        permissions: List[Dict[str, any]]
    ) -> RBACPolicy:
        """
        Update an existing RBAC policy for a tenant.

        Convenience method that updates a policy and clears the cache
        for the tenant to ensure the updated policy is loaded on next access.

        Args:
            db: Database session (must be set to tenant schema)
            tenant_id: Tenant identifier
            role: Role name
            permissions: New list of permission dictionaries

        Returns:
            RBACPolicy: Updated policy object

        Requirements: 3.5

        Example:
            engine = RBACEngine()
            policy = await engine.update_tenant_policy(
                db=session,
                tenant_id="tenant_abc",
                role="analyst",
                permissions=[
                    {"action": "read", "resource": "*"},
                    {"action": "create", "resource": "reports"},
                    {"action": "update", "resource": "reports"}
                ]
            )
        """
        from app.auth.rbac_policy_manager import RBACPolicyManager

        manager = RBACPolicyManager()
        policy = await manager.update_policy(db, role, permissions, tenant_id)

        # Clear cache to force reload on next access
        self.clear_cache(tenant_id)

        return policy

    async def delete_tenant_policy(
        self,
        db: AsyncSession,
        tenant_id: str,
        role: str
    ) -> bool:
        """
        Delete an RBAC policy for a tenant.

        Convenience method that deletes a policy and clears the cache
        for the tenant.

        Args:
            db: Database session (must be set to tenant schema)
            tenant_id: Tenant identifier
            role: Role name to delete

        Returns:
            bool: True if policy was deleted, False if not found

        Requirements: 3.5

        Example:
            engine = RBACEngine()
            deleted = await engine.delete_tenant_policy(
                db=session,
                tenant_id="tenant_abc",
                role="old_role"
            )
        """
        from app.auth.rbac_policy_manager import RBACPolicyManager

        manager = RBACPolicyManager()
        deleted = await manager.delete_policy(db, role, tenant_id)

        # Clear cache to force reload on next access
        self.clear_cache(tenant_id)

        return deleted

