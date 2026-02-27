"""
Shared Platform Schema Models

This module defines SQLAlchemy models for the platform_shared schema,
which contains data shared across all tenants including tenant registry,
rate limit configurations, usage metrics, and autoscaling events.

Requirements: 1.1, 5.1, 6.1, 8.4
"""

from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy import (
    String,
    Integer,
    Float,
    Text,
    DateTime,
    Index,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import SharedBase


class Tenant(SharedBase):
    """
    Tenant registry model.
    
    Stores information about each tenant organization including their
    tier, status, and timestamps. This is the authoritative source for
    tenant existence and configuration.
    
    Requirements: 1.1
    """
    
    __tablename__ = "tenants"
    __table_args__ = {"schema": "platform_shared"}
    
    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        comment="Unique tenant identifier"
    )
    organization_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Organization name for the tenant"
    )
    tier: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="Subscription tier: free, pro, enterprise"
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        server_default=text("'active'"),
        comment="Tenant status: active, suspended, deleted"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("NOW()"),
        comment="Timestamp when tenant was created"
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("NOW()"),
        onupdate=datetime.utcnow,
        comment="Timestamp when tenant was last updated"
    )
    
    def __repr__(self) -> str:
        return f"<Tenant(id={self.id}, organization={self.organization_name}, tier={self.tier})>"


class RateLimitConfig(SharedBase):
    """
    Rate limit configuration model.
    
    Stores per-tenant rate limiting configuration including maximum
    requests allowed and time window. Used by the rate limiter to
    enforce tenant-specific request quotas.
    
    Requirements: 6.1
    """
    
    __tablename__ = "rate_limit_configs"
    __table_args__ = {"schema": "platform_shared"}
    
    tenant_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        comment="Tenant identifier (foreign key to tenants.id)"
    )
    max_requests: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Maximum number of requests allowed in the time window"
    )
    window_seconds: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Time window in seconds for rate limiting"
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("NOW()"),
        onupdate=datetime.utcnow,
        comment="Timestamp when configuration was last updated"
    )
    
    def __repr__(self) -> str:
        return f"<RateLimitConfig(tenant_id={self.tenant_id}, max_requests={self.max_requests}, window={self.window_seconds}s)>"


class UsageMetric(SharedBase):
    """
    Usage metrics model.
    
    Stores usage metrics for all tenants including API request counts,
    compute time, and data transfer. This table is designed as a
    TimescaleDB hypertable for efficient time-series data storage and
    querying.
    
    Requirements: 5.1
    """
    
    __tablename__ = "usage_metrics"
    __table_args__ = (
        Index(
            "idx_usage_metrics_tenant_time",
            "tenant_id",
            "timestamp",
            postgresql_using="btree"
        ),
        Index(
            "idx_usage_metrics_type",
            "metric_type",
            postgresql_using="btree"
        ),
        {"schema": "platform_shared"}
    )
    
    tenant_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        comment="Tenant identifier"
    )
    metric_type: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        comment="Type of metric: api_request, compute_time, data_transfer"
    )
    value: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Numeric value of the metric"
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime,
        primary_key=True,
        nullable=False,
        comment="Timestamp when metric was recorded"
    )
    extra_metadata: Mapped[Optional[dict]] = mapped_column(
        "metadata",
        JSONB,
        nullable=True,
        comment="Additional metadata about the metric (endpoint, method, status_code, etc.)"
    )
    
    def __repr__(self) -> str:
        return f"<UsageMetric(tenant_id={self.tenant_id}, type={self.metric_type}, value={self.value}, timestamp={self.timestamp})>"


class ScalingEvent(SharedBase):
    """
    Scaling event model.
    
    Stores autoscaling decisions and events for each tenant. Records
    when the autoscaling engine decides to scale resources up or down,
    including the reason and capacity changes.
    
    Requirements: 8.4
    """
    
    __tablename__ = "scaling_events"
    __table_args__ = (
        Index(
            "idx_scaling_events_tenant",
            "tenant_id",
            "timestamp",
            postgresql_using="btree",
            postgresql_ops={"timestamp": "DESC"}
        ),
        {"schema": "platform_shared"}
    )
    
    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
        comment="Unique identifier for the scaling event"
    )
    tenant_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Tenant identifier"
    )
    action: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="Scaling action: scale_up, scale_down"
    )
    reason: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Reason for the scaling decision"
    )
    current_capacity: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Current resource capacity before scaling"
    )
    target_capacity: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Target resource capacity after scaling"
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("NOW()"),
        comment="Timestamp when scaling event occurred"
    )
    
    def __repr__(self) -> str:
        return f"<ScalingEvent(id={self.id}, tenant_id={self.tenant_id}, action={self.action}, timestamp={self.timestamp})>"
