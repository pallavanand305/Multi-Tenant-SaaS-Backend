"""
Tenant Router

This module provides the TenantRouter class that manages database connections
with tenant-specific schema routing using PostgreSQL search_path.

Requirements: 1.1, 1.2, 1.4
"""

from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession, AsyncEngine, async_sessionmaker
from sqlalchemy import text
import structlog

from app.config import settings

logger = structlog.get_logger(__name__)


class TenantRouter:
    """
    Manages database connections with tenant-specific schema routing.
    
    The TenantRouter ensures tenant isolation by setting PostgreSQL search_path
    to the tenant-specific schema for each database session. This guarantees
    that all queries execute within the correct tenant context.
    
    Requirements:
    - 1.1: Identify tenant from request context
    - 1.2: Route database operations to correct tenant schema
    - 1.4: Validate tenant context matches connection target
    """
    
    def __init__(self, engine: AsyncEngine):
        """
        Initialize TenantRouter with database engine.
        
        Args:
            engine: SQLAlchemy async engine for database connections
        """
        self.engine = engine
        self.session_factory = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )
        logger.info("TenantRouter initialized")
    
    async def get_session(self, tenant_id: str) -> AsyncSession:
        """
        Get database session with tenant schema set.
        
        Creates a new database session and sets the PostgreSQL search_path
        to the tenant-specific schema. All subsequent queries in this session
        will execute within the tenant's schema, ensuring data isolation.
        
        The search_path is set to: tenant_{tenant_id}, public
        This allows access to tenant-specific tables first, with fallback to public schema.
        
        Args:
            tenant_id: Unique identifier for the tenant
            
        Returns:
            AsyncSession: Database session configured for tenant schema
            
        Raises:
            ValueError: If tenant_id is empty or invalid
            
        Requirements:
        - 1.2: Route all database operations to correct tenant schema
        - 1.4: Validate tenant context matches connection target
        
        Example:
            session = await tenant_router.get_session("tenant_abc123")
            # All queries in this session are scoped to tenant_abc123 schema
            result = await session.execute(select(User))
        """
        if not tenant_id or not isinstance(tenant_id, str):
            raise ValueError("tenant_id must be a non-empty string")
        
        # Sanitize tenant_id to prevent SQL injection
        # Only allow alphanumeric characters and underscores
        if not tenant_id.replace("_", "").isalnum():
            raise ValueError("tenant_id contains invalid characters")
        
        # Create new session
        session = self.session_factory()
        
        try:
            # Set search_path to tenant schema
            # Format: tenant_{tenant_id}, public
            # This ensures queries look in tenant schema first, then public
            schema_name = f"tenant_{tenant_id}"
            await session.execute(
                text(f"SET search_path TO {schema_name}, public")
            )
            
            logger.debug(
                "Database session created with tenant context",
                tenant_id=tenant_id,
                schema=schema_name
            )
            
            return session
            
        except Exception as e:
            # Close session if search_path setting fails
            await session.close()
            logger.error(
                "Failed to set tenant search_path",
                tenant_id=tenant_id,
                error=str(e)
            )
            raise
    
    async def validate_tenant(self, tenant_id: str) -> bool:
        """
        Verify tenant exists and is active.
        
        Queries the platform_shared.tenants table to check if the tenant
        exists and has an 'active' status. This validation should be performed
        before routing requests to ensure the tenant is valid.
        
        Args:
            tenant_id: Unique identifier for the tenant
            
        Returns:
            bool: True if tenant exists and is active, False otherwise
            
        Requirements:
        - 1.4: Validate tenant context matches connection target
        
        Example:
            is_valid = await tenant_router.validate_tenant("tenant_abc123")
            if not is_valid:
                raise HTTPException(status_code=404, detail="Tenant not found")
        """
        if not tenant_id or not isinstance(tenant_id, str):
            logger.warning("Invalid tenant_id provided for validation", tenant_id=tenant_id)
            return False
        
        async with self.session_factory() as session:
            try:
                # Set search_path to shared schema
                await session.execute(text("SET search_path TO platform_shared, public"))
                
                # Query tenant existence and status
                result = await session.execute(
                    text(
                        "SELECT id, status FROM tenants WHERE id = :tenant_id"
                    ),
                    {"tenant_id": tenant_id}
                )
                
                row = result.fetchone()
                
                if row is None:
                    logger.warning("Tenant not found", tenant_id=tenant_id)
                    return False
                
                tenant_status = row[1]
                is_active = tenant_status == "active"
                
                if not is_active:
                    logger.warning(
                        "Tenant is not active",
                        tenant_id=tenant_id,
                        status=tenant_status
                    )
                
                return is_active
                
            except Exception as e:
                logger.error(
                    "Error validating tenant",
                    tenant_id=tenant_id,
                    error=str(e)
                )
                return False
    
    async def create_tenant_schema(self, tenant_id: str) -> None:
        """
        Create new schema and initialize tables for tenant.
        
        Creates a new PostgreSQL schema for the tenant and initializes all
        tenant-specific tables. This is called during tenant onboarding.
        
        The schema name follows the pattern: tenant_{tenant_id}
        
        Tables created:
        - users: Tenant users
        - api_keys: API keys for tenant
        - rbac_policies: Role-based access control policies
        - resources: Tenant-specific resources
        - jobs: Background job tracking
        - audit_logs: Audit trail for tenant actions
        
        Args:
            tenant_id: Unique identifier for the tenant
            
        Raises:
            ValueError: If tenant_id is invalid
            Exception: If schema creation fails
            
        Requirements:
        - 1.1: Support tenant identification and routing
        - 1.2: Create isolated database schema for tenant
        
        Example:
            await tenant_router.create_tenant_schema("tenant_abc123")
            # Schema tenant_abc123 is now created with all tables
        """
        if not tenant_id or not isinstance(tenant_id, str):
            raise ValueError("tenant_id must be a non-empty string")
        
        # Sanitize tenant_id
        if not tenant_id.replace("_", "").isalnum():
            raise ValueError("tenant_id contains invalid characters")
        
        schema_name = f"tenant_{tenant_id}"
        
        async with self.session_factory() as session:
            try:
                # Create schema
                await session.execute(text(f"CREATE SCHEMA IF NOT EXISTS {schema_name}"))
                
                # Set search_path to new schema
                await session.execute(text(f"SET search_path TO {schema_name}, public"))
                
                # Create users table
                await session.execute(text("""
                    CREATE TABLE IF NOT EXISTS users (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        email VARCHAR(255) UNIQUE NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        role VARCHAR(32) NOT NULL,
                        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMP NOT NULL DEFAULT NOW()
                    )
                """))
                
                # Create api_keys table
                await session.execute(text("""
                    CREATE TABLE IF NOT EXISTS api_keys (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        key_prefix VARCHAR(16) NOT NULL,
                        hashed_secret VARCHAR(255) NOT NULL,
                        name VARCHAR(255) NOT NULL,
                        role VARCHAR(32) NOT NULL,
                        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                        revoked_at TIMESTAMP,
                        last_used_at TIMESTAMP
                    )
                """))
                
                # Create index on api_keys
                await session.execute(text("""
                    CREATE INDEX IF NOT EXISTS idx_api_keys_prefix 
                    ON api_keys(key_prefix) 
                    WHERE revoked_at IS NULL
                """))
                
                # Create rbac_policies table
                await session.execute(text("""
                    CREATE TABLE IF NOT EXISTS rbac_policies (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        role VARCHAR(32) NOT NULL UNIQUE,
                        permissions JSONB NOT NULL,
                        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMP NOT NULL DEFAULT NOW()
                    )
                """))
                
                # Create resources table
                await session.execute(text("""
                    CREATE TABLE IF NOT EXISTS resources (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        name VARCHAR(255) NOT NULL,
                        data JSONB NOT NULL,
                        owner_id UUID REFERENCES users(id),
                        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMP NOT NULL DEFAULT NOW()
                    )
                """))
                
                # Create jobs table
                await session.execute(text("""
                    CREATE TABLE IF NOT EXISTS jobs (
                        id UUID PRIMARY KEY,
                        task_type VARCHAR(64) NOT NULL,
                        status VARCHAR(32) NOT NULL,
                        payload JSONB,
                        result JSONB,
                        error TEXT,
                        created_by UUID REFERENCES users(id),
                        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                        started_at TIMESTAMP,
                        completed_at TIMESTAMP
                    )
                """))
                
                # Create index on jobs
                await session.execute(text("""
                    CREATE INDEX IF NOT EXISTS idx_jobs_status 
                    ON jobs(status, created_at DESC)
                """))
                
                # Create audit_logs table
                await session.execute(text("""
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        user_id UUID REFERENCES users(id),
                        action VARCHAR(64) NOT NULL,
                        resource_type VARCHAR(64),
                        resource_id UUID,
                        changes JSONB,
                        ip_address INET,
                        timestamp TIMESTAMP NOT NULL DEFAULT NOW()
                    )
                """))
                
                # Create indexes on audit_logs
                await session.execute(text("""
                    CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp 
                    ON audit_logs(timestamp DESC)
                """))
                
                await session.execute(text("""
                    CREATE INDEX IF NOT EXISTS idx_audit_logs_user 
                    ON audit_logs(user_id, timestamp DESC)
                """))
                
                # Commit all changes
                await session.commit()
                
                logger.info(
                    "Tenant schema created successfully",
                    tenant_id=tenant_id,
                    schema=schema_name
                )
                
            except Exception as e:
                await session.rollback()
                logger.error(
                    "Failed to create tenant schema",
                    tenant_id=tenant_id,
                    schema=schema_name,
                    error=str(e)
                )
                raise
