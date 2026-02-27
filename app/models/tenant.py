"""
Tenant-Specific Schema Models

This module defines SQLAlchemy models for tenant-specific schemas (tenant_{tenant_id}).
Each tenant has their own isolated schema containing users, API keys, RBAC policies,
resources, background jobs, and audit logs. This ensures complete data isolation
between tenants at the database level.

Requirements: 1.2, 2.1, 3.1, 4.1
"""

from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy import (
    String,
    Text,
    DateTime,
    Index,
    ForeignKey,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import TenantBase


class User(TenantBase):
    """
    User model for tenant-specific users.
    
    Stores user credentials and role information within a tenant's schema.
    Each tenant has their own isolated set of users that cannot access
    other tenants' data.
    
    Requirements: 2.1
    """
    
    __tablename__ = "users"
    
    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
        comment="Unique user identifier"
    )
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        comment="User email address (unique within tenant)"
    )
    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Bcrypt hashed password"
    )
    role: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="User role: admin, developer, read_only"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("NOW()"),
        comment="Timestamp when user was created"
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("NOW()"),
        onupdate=datetime.utcnow,
        comment="Timestamp when user was last updated"
    )
    
    # Relationships
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    resources = relationship("Resource", back_populates="owner", cascade="all, delete-orphan")
    jobs = relationship("Job", back_populates="creator", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self) -> str:
        return f"<User(id={self.id}, email={self.email}, role={self.role})>"


class APIKey(TenantBase):
    """
    API key model for tenant authentication.
    
    Stores API keys that can be used to authenticate requests without
    user credentials. Each key is associated with a specific role and
    can be revoked independently.
    
    Requirements: 4.1
    """
    
    __tablename__ = "api_keys"
    __table_args__ = (
        Index(
            "idx_api_keys_prefix",
            "key_prefix",
            postgresql_where=text("revoked_at IS NULL"),
            postgresql_using="btree"
        ),
    )
    
    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
        comment="Unique API key identifier"
    )
    key_prefix: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        comment="First 8 characters of the key for identification"
    )
    hashed_secret: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Bcrypt hashed API key secret"
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Human-readable name for the API key"
    )
    role: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="Role associated with this API key"
    )
    created_by: Mapped[Optional[UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User who created this API key"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("NOW()"),
        comment="Timestamp when API key was created"
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Timestamp when API key was revoked (NULL if active)"
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Timestamp when API key was last used"
    )
    
    # Relationships
    user = relationship("User", back_populates="api_keys")
    
    def __repr__(self) -> str:
        status = "revoked" if self.revoked_at else "active"
        return f"<APIKey(id={self.id}, name={self.name}, role={self.role}, status={status})>"


class RBACPolicy(TenantBase):
    """
    RBAC policy model for tenant-specific authorization.
    
    Stores role-based access control policies that define what actions
    each role can perform. Policies are configurable per tenant, allowing
    each organization to customize their security model.
    
    Requirements: 3.1
    """
    
    __tablename__ = "rbac_policies"
    
    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
        comment="Unique policy identifier"
    )
    role: Mapped[str] = mapped_column(
        String(32),
        unique=True,
        nullable=False,
        comment="Role name: admin, developer, read_only, or custom"
    )
    permissions: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        comment="JSON array of permissions: [{action, resource, conditions}]"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("NOW()"),
        comment="Timestamp when policy was created"
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("NOW()"),
        onupdate=datetime.utcnow,
        comment="Timestamp when policy was last updated"
    )
    
    def __repr__(self) -> str:
        return f"<RBACPolicy(id={self.id}, role={self.role})>"


class Resource(TenantBase):
    """
    Resource model for tenant-specific data.
    
    Example model representing tenant-owned resources. This demonstrates
    how tenant-specific data is stored in isolated schemas with proper
    ownership tracking and audit trails.
    
    Requirements: 1.2
    """
    
    __tablename__ = "resources"
    __table_args__ = (
        Index(
            "idx_resources_owner",
            "owner_id",
            postgresql_using="btree"
        ),
        Index(
            "idx_resources_created",
            "created_at",
            postgresql_using="btree",
            postgresql_ops={"created_at": "DESC"}
        ),
    )
    
    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
        comment="Unique resource identifier"
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Resource name"
    )
    data: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        comment="Resource data stored as JSON"
    )
    owner_id: Mapped[Optional[UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User who owns this resource"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("NOW()"),
        comment="Timestamp when resource was created"
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("NOW()"),
        onupdate=datetime.utcnow,
        comment="Timestamp when resource was last updated"
    )
    
    # Relationships
    owner = relationship("User", back_populates="resources")
    
    def __repr__(self) -> str:
        return f"<Resource(id={self.id}, name={self.name}, owner_id={self.owner_id})>"


class Job(TenantBase):
    """
    Background job tracking model.
    
    Stores information about background jobs executed for the tenant,
    including status, payload, results, and error information. Enables
    job status queries and debugging.
    
    Requirements: 1.2
    """
    
    __tablename__ = "jobs"
    __table_args__ = (
        Index(
            "idx_jobs_status",
            "status",
            "created_at",
            postgresql_using="btree",
            postgresql_ops={"created_at": "DESC"}
        ),
        Index(
            "idx_jobs_creator",
            "created_by",
            postgresql_using="btree"
        ),
    )
    
    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        comment="Job identifier (matches Celery task ID)"
    )
    task_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Type of background task"
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="Job status: PENDING, STARTED, SUCCESS, FAILURE, RETRY"
    )
    payload: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        nullable=True,
        comment="Job input payload"
    )
    result: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        nullable=True,
        comment="Job result data (on success)"
    )
    error: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Error message (on failure)"
    )
    created_by: Mapped[Optional[UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User who created this job"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("NOW()"),
        comment="Timestamp when job was created"
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Timestamp when job execution started"
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Timestamp when job completed (success or failure)"
    )
    
    # Relationships
    creator = relationship("User", back_populates="jobs")
    
    def __repr__(self) -> str:
        return f"<Job(id={self.id}, task_type={self.task_type}, status={self.status})>"


class AuditLog(TenantBase):
    """
    Audit log model for tracking tenant actions.
    
    Records all significant actions performed within the tenant for
    security auditing, compliance, and debugging. Includes user actions,
    resource changes, and system events.
    
    Requirements: 1.2
    """
    
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index(
            "idx_audit_logs_timestamp",
            "timestamp",
            postgresql_using="btree",
            postgresql_ops={"timestamp": "DESC"}
        ),
        Index(
            "idx_audit_logs_user",
            "user_id",
            "timestamp",
            postgresql_using="btree",
            postgresql_ops={"timestamp": "DESC"}
        ),
        Index(
            "idx_audit_logs_resource",
            "resource_type",
            "resource_id",
            postgresql_using="btree"
        ),
    )
    
    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
        comment="Unique audit log identifier"
    )
    user_id: Mapped[Optional[UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User who performed the action"
    )
    action: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Action performed: create, read, update, delete, login, etc."
    )
    resource_type: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        comment="Type of resource affected: user, api_key, resource, job, etc."
    )
    resource_id: Mapped[Optional[UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        comment="Identifier of the affected resource"
    )
    changes: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        nullable=True,
        comment="JSON object describing changes made (before/after values)"
    )
    ip_address: Mapped[Optional[str]] = mapped_column(
        INET,
        nullable=True,
        comment="IP address of the client making the request"
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("NOW()"),
        comment="Timestamp when action occurred"
    )
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")
    
    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, action={self.action}, user_id={self.user_id}, timestamp={self.timestamp})>"
