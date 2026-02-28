"""
RBAC Policy Manager

Manages tenant-specific RBAC policies including creation, updates, and deletion.
Provides methods to configure custom roles and permissions per tenant.

Requirements: 3.5
"""

from typing import List, Dict, Optional
from uuid import UUID
import structlog

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from sqlalchemy.exc import IntegrityError

from app.models.tenant import RBACPolicy


logger = structlog.get_logger(__name__)


class RBACPolicyManager:
    """
    Manager for tenant-specific RBAC policy operations.
    
    Provides methods to create, update, delete, and query RBAC policies
    stored in tenant schemas. Each tenant can define custom roles with
    specific permissions tailored to their security requirements.
    
    Requirements: 3.5
    """
    
    async def create_policy(
        self,
        db: AsyncSession,
        role: str,
        permissions: List[Dict[str, any]],
        tenant_id: Optional[str] = None
    ) -> RBACPolicy:
        """
        Create a new RBAC policy for a role.
        
        Creates a new role with specified permissions in the tenant's schema.
        The database session must already be set to the correct tenant schema.
        
        Args:
            db: Database session (must be set to tenant schema)
            role: Role name (e.g., "custom_admin", "analyst", "viewer")
            permissions: List of permission dictionaries with format:
                [
                    {"action": "read", "resource": "users", "conditions": {}},
                    {"action": "create", "resource": "resources", "conditions": {}}
                ]
            tenant_id: Optional tenant identifier for logging purposes
        
        Returns:
            RBACPolicy: Created policy object
        
        Raises:
            IntegrityError: If role already exists
            ValueError: If permissions format is invalid
        
        Requirements: 3.5
        
        Example:
            manager = RBACPolicyManager()
            policy = await manager.create_policy(
                db=session,
                role="analyst",
                permissions=[
                    {"action": "read", "resource": "*"},
                    {"action": "create", "resource": "reports"}
                ],
                tenant_id="tenant_abc"
            )
        """
        # Validate permissions format
        self._validate_permissions(permissions)
        
        try:
            # Create new policy
            policy = RBACPolicy(
                role=role,
                permissions=permissions
            )
            
            db.add(policy)
            await db.commit()
            await db.refresh(policy)
            
            logger.info(
                "Created RBAC policy",
                tenant_id=tenant_id,
                role=role,
                permission_count=len(permissions)
            )
            
            return policy
            
        except IntegrityError as e:
            await db.rollback()
            logger.error(
                "Failed to create RBAC policy - role already exists",
                tenant_id=tenant_id,
                role=role,
                error=str(e)
            )
            raise ValueError(f"Role '{role}' already exists") from e
        except Exception as e:
            await db.rollback()
            logger.error(
                "Failed to create RBAC policy",
                tenant_id=tenant_id,
                role=role,
                error=str(e)
            )
            raise
    
    async def update_policy(
        self,
        db: AsyncSession,
        role: str,
        permissions: List[Dict[str, any]],
        tenant_id: Optional[str] = None
    ) -> RBACPolicy:
        """
        Update an existing RBAC policy.
        
        Updates the permissions for an existing role. The database session
        must already be set to the correct tenant schema.
        
        Args:
            db: Database session (must be set to tenant schema)
            role: Role name to update
            permissions: New list of permission dictionaries
            tenant_id: Optional tenant identifier for logging purposes
        
        Returns:
            RBACPolicy: Updated policy object
        
        Raises:
            ValueError: If role doesn't exist or permissions format is invalid
        
        Requirements: 3.5
        
        Example:
            manager = RBACPolicyManager()
            policy = await manager.update_policy(
                db=session,
                role="analyst",
                permissions=[
                    {"action": "read", "resource": "*"},
                    {"action": "create", "resource": "reports"},
                    {"action": "update", "resource": "reports"}
                ],
                tenant_id="tenant_abc"
            )
        """
        # Validate permissions format
        self._validate_permissions(permissions)
        
        try:
            # Find existing policy
            stmt = select(RBACPolicy).where(RBACPolicy.role == role)
            result = await db.execute(stmt)
            policy = result.scalar_one_or_none()
            
            if policy is None:
                logger.warning(
                    "RBAC policy not found for update",
                    tenant_id=tenant_id,
                    role=role
                )
                raise ValueError(f"Role '{role}' does not exist")
            
            # Update permissions
            policy.permissions = permissions
            
            await db.commit()
            await db.refresh(policy)
            
            logger.info(
                "Updated RBAC policy",
                tenant_id=tenant_id,
                role=role,
                permission_count=len(permissions)
            )
            
            return policy
            
        except ValueError:
            await db.rollback()
            raise
        except Exception as e:
            await db.rollback()
            logger.error(
                "Failed to update RBAC policy",
                tenant_id=tenant_id,
                role=role,
                error=str(e)
            )
            raise
    
    async def delete_policy(
        self,
        db: AsyncSession,
        role: str,
        tenant_id: Optional[str] = None
    ) -> bool:
        """
        Delete an RBAC policy.
        
        Removes a role and its permissions from the tenant's schema.
        The database session must already be set to the correct tenant schema.
        
        Args:
            db: Database session (must be set to tenant schema)
            role: Role name to delete
            tenant_id: Optional tenant identifier for logging purposes
        
        Returns:
            bool: True if policy was deleted, False if not found
        
        Requirements: 3.5
        
        Example:
            manager = RBACPolicyManager()
            deleted = await manager.delete_policy(
                db=session,
                role="old_role",
                tenant_id="tenant_abc"
            )
        """
        try:
            # Delete policy
            stmt = delete(RBACPolicy).where(RBACPolicy.role == role)
            result = await db.execute(stmt)
            await db.commit()
            
            deleted = result.rowcount > 0
            
            if deleted:
                logger.info(
                    "Deleted RBAC policy",
                    tenant_id=tenant_id,
                    role=role
                )
            else:
                logger.warning(
                    "RBAC policy not found for deletion",
                    tenant_id=tenant_id,
                    role=role
                )
            
            return deleted
            
        except Exception as e:
            await db.rollback()
            logger.error(
                "Failed to delete RBAC policy",
                tenant_id=tenant_id,
                role=role,
                error=str(e)
            )
            raise
    
    async def get_policy(
        self,
        db: AsyncSession,
        role: str,
        tenant_id: Optional[str] = None
    ) -> Optional[RBACPolicy]:
        """
        Get an RBAC policy by role name.
        
        Retrieves a specific policy from the tenant's schema.
        The database session must already be set to the correct tenant schema.
        
        Args:
            db: Database session (must be set to tenant schema)
            role: Role name to retrieve
            tenant_id: Optional tenant identifier for logging purposes
        
        Returns:
            RBACPolicy or None: Policy object if found, None otherwise
        
        Requirements: 3.5
        
        Example:
            manager = RBACPolicyManager()
            policy = await manager.get_policy(
                db=session,
                role="analyst",
                tenant_id="tenant_abc"
            )
        """
        try:
            stmt = select(RBACPolicy).where(RBACPolicy.role == role)
            result = await db.execute(stmt)
            policy = result.scalar_one_or_none()
            
            if policy:
                logger.debug(
                    "Retrieved RBAC policy",
                    tenant_id=tenant_id,
                    role=role
                )
            else:
                logger.debug(
                    "RBAC policy not found",
                    tenant_id=tenant_id,
                    role=role
                )
            
            return policy
            
        except Exception as e:
            logger.error(
                "Failed to retrieve RBAC policy",
                tenant_id=tenant_id,
                role=role,
                error=str(e)
            )
            raise
    
    async def list_policies(
        self,
        db: AsyncSession,
        tenant_id: Optional[str] = None
    ) -> List[RBACPolicy]:
        """
        List all RBAC policies for a tenant.
        
        Retrieves all policies from the tenant's schema.
        The database session must already be set to the correct tenant schema.
        
        Args:
            db: Database session (must be set to tenant schema)
            tenant_id: Optional tenant identifier for logging purposes
        
        Returns:
            List[RBACPolicy]: List of all policy objects
        
        Requirements: 3.5
        
        Example:
            manager = RBACPolicyManager()
            policies = await manager.list_policies(
                db=session,
                tenant_id="tenant_abc"
            )
        """
        try:
            stmt = select(RBACPolicy).order_by(RBACPolicy.role)
            result = await db.execute(stmt)
            policies = result.scalars().all()
            
            logger.debug(
                "Listed RBAC policies",
                tenant_id=tenant_id,
                count=len(policies)
            )
            
            return list(policies)
            
        except Exception as e:
            logger.error(
                "Failed to list RBAC policies",
                tenant_id=tenant_id,
                error=str(e)
            )
            raise
    
    async def upsert_policy(
        self,
        db: AsyncSession,
        role: str,
        permissions: List[Dict[str, any]],
        tenant_id: Optional[str] = None
    ) -> RBACPolicy:
        """
        Create or update an RBAC policy.
        
        If the role exists, updates its permissions. If it doesn't exist,
        creates a new policy. This is a convenience method for idempotent
        policy management.
        
        Args:
            db: Database session (must be set to tenant schema)
            role: Role name
            permissions: List of permission dictionaries
            tenant_id: Optional tenant identifier for logging purposes
        
        Returns:
            RBACPolicy: Created or updated policy object
        
        Requirements: 3.5
        
        Example:
            manager = RBACPolicyManager()
            policy = await manager.upsert_policy(
                db=session,
                role="analyst",
                permissions=[
                    {"action": "read", "resource": "*"}
                ],
                tenant_id="tenant_abc"
            )
        """
        # Check if policy exists
        existing = await self.get_policy(db, role, tenant_id)
        
        if existing:
            return await self.update_policy(db, role, permissions, tenant_id)
        else:
            return await self.create_policy(db, role, permissions, tenant_id)
    
    def _validate_permissions(self, permissions: List[Dict[str, any]]) -> None:
        """
        Validate permissions format.
        
        Ensures that permissions list contains valid permission dictionaries
        with required fields.
        
        Args:
            permissions: List of permission dictionaries to validate
        
        Raises:
            ValueError: If permissions format is invalid
        """
        if not isinstance(permissions, list):
            raise ValueError("Permissions must be a list")
        
        for i, perm in enumerate(permissions):
            if not isinstance(perm, dict):
                raise ValueError(f"Permission at index {i} must be a dictionary")
            
            if "action" not in perm:
                raise ValueError(f"Permission at index {i} missing 'action' field")
            
            if "resource" not in perm:
                raise ValueError(f"Permission at index {i} missing 'resource' field")
            
            # Validate action and resource are strings
            if not isinstance(perm["action"], str):
                raise ValueError(f"Permission at index {i} 'action' must be a string")
            
            if not isinstance(perm["resource"], str):
                raise ValueError(f"Permission at index {i} 'resource' must be a string")
            
            # Conditions are optional but must be dict if present
            if "conditions" in perm and not isinstance(perm["conditions"], dict):
                raise ValueError(f"Permission at index {i} 'conditions' must be a dictionary")
