"""
Unit tests for shared platform schema models.

Tests the SQLAlchemy model definitions for Tenant, RateLimitConfig,
UsageMetric, and ScalingEvent models.
"""

import pytest
from datetime import datetime
from uuid import uuid4

from app.models.shared import (
    Tenant,
    RateLimitConfig,
    UsageMetric,
    ScalingEvent,
)


class TestTenantModel:
    """Test cases for Tenant model"""
    
    def test_tenant_model_attributes(self):
        """Test that Tenant model has all required attributes"""
        tenant = Tenant(
            id="tenant_test123",
            organization_name="Test Organization",
            tier="pro",
            status="active",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        
        assert tenant.id == "tenant_test123"
        assert tenant.organization_name == "Test Organization"
        assert tenant.tier == "pro"
        assert tenant.status == "active"
        assert isinstance(tenant.created_at, datetime)
        assert isinstance(tenant.updated_at, datetime)
    
    def test_tenant_repr(self):
        """Test Tenant string representation"""
        tenant = Tenant(
            id="tenant_test123",
            organization_name="Test Org",
            tier="free",
        )
        
        repr_str = repr(tenant)
        assert "tenant_test123" in repr_str
        assert "Test Org" in repr_str
        assert "free" in repr_str
    
    def test_tenant_table_name(self):
        """Test that Tenant uses correct table name and schema"""
        assert Tenant.__tablename__ == "tenants"
        assert Tenant.__table_args__["schema"] == "platform_shared"


class TestRateLimitConfigModel:
    """Test cases for RateLimitConfig model"""
    
    def test_rate_limit_config_attributes(self):
        """Test that RateLimitConfig model has all required attributes"""
        config = RateLimitConfig(
            tenant_id="tenant_test123",
            max_requests=1000,
            window_seconds=60,
            updated_at=datetime.utcnow(),
        )
        
        assert config.tenant_id == "tenant_test123"
        assert config.max_requests == 1000
        assert config.window_seconds == 60
        assert isinstance(config.updated_at, datetime)
    
    def test_rate_limit_config_repr(self):
        """Test RateLimitConfig string representation"""
        config = RateLimitConfig(
            tenant_id="tenant_test123",
            max_requests=500,
            window_seconds=30,
        )
        
        repr_str = repr(config)
        assert "tenant_test123" in repr_str
        assert "500" in repr_str
        assert "30s" in repr_str
    
    def test_rate_limit_config_table_name(self):
        """Test that RateLimitConfig uses correct table name and schema"""
        assert RateLimitConfig.__tablename__ == "rate_limit_configs"
        assert RateLimitConfig.__table_args__["schema"] == "platform_shared"


class TestUsageMetricModel:
    """Test cases for UsageMetric model"""
    
    def test_usage_metric_attributes(self):
        """Test that UsageMetric model has all required attributes"""
        metric = UsageMetric(
            tenant_id="tenant_test123",
            metric_type="api_request",
            value=1.0,
            timestamp=datetime.utcnow(),
            extra_metadata={"endpoint": "/api/v1/resources", "method": "GET"},
        )
        
        assert metric.tenant_id == "tenant_test123"
        assert metric.metric_type == "api_request"
        assert metric.value == 1.0
        assert isinstance(metric.timestamp, datetime)
        assert metric.extra_metadata["endpoint"] == "/api/v1/resources"
        assert metric.extra_metadata["method"] == "GET"
    
    def test_usage_metric_without_metadata(self):
        """Test UsageMetric with optional metadata field"""
        metric = UsageMetric(
            tenant_id="tenant_test123",
            metric_type="compute_time",
            value=45.2,
            timestamp=datetime.utcnow(),
        )
        
        assert metric.tenant_id == "tenant_test123"
        assert metric.metric_type == "compute_time"
        assert metric.value == 45.2
        assert metric.extra_metadata is None
    
    def test_usage_metric_repr(self):
        """Test UsageMetric string representation"""
        timestamp = datetime.utcnow()
        metric = UsageMetric(
            tenant_id="tenant_test123",
            metric_type="data_transfer",
            value=1024.5,
            timestamp=timestamp,
        )
        
        repr_str = repr(metric)
        assert "tenant_test123" in repr_str
        assert "data_transfer" in repr_str
        assert "1024.5" in repr_str
    
    def test_usage_metric_table_name(self):
        """Test that UsageMetric uses correct table name and schema"""
        assert UsageMetric.__tablename__ == "usage_metrics"
        assert UsageMetric.__table_args__[-1]["schema"] == "platform_shared"


class TestScalingEventModel:
    """Test cases for ScalingEvent model"""
    
    def test_scaling_event_attributes(self):
        """Test that ScalingEvent model has all required attributes"""
        event_id = uuid4()
        event = ScalingEvent(
            id=event_id,
            tenant_id="tenant_test123",
            action="scale_up",
            reason="High load: 1500 req/min",
            current_capacity=2,
            target_capacity=4,
            timestamp=datetime.utcnow(),
        )
        
        assert event.id == event_id
        assert event.tenant_id == "tenant_test123"
        assert event.action == "scale_up"
        assert event.reason == "High load: 1500 req/min"
        assert event.current_capacity == 2
        assert event.target_capacity == 4
        assert isinstance(event.timestamp, datetime)
    
    def test_scaling_event_optional_fields(self):
        """Test ScalingEvent with optional fields"""
        event = ScalingEvent(
            tenant_id="tenant_test123",
            action="scale_down",
            timestamp=datetime.utcnow(),
        )
        
        assert event.tenant_id == "tenant_test123"
        assert event.action == "scale_down"
        assert event.reason is None
        assert event.current_capacity is None
        assert event.target_capacity is None
    
    def test_scaling_event_repr(self):
        """Test ScalingEvent string representation"""
        event_id = uuid4()
        timestamp = datetime.utcnow()
        event = ScalingEvent(
            id=event_id,
            tenant_id="tenant_test123",
            action="scale_up",
            timestamp=timestamp,
        )
        
        repr_str = repr(event)
        assert "tenant_test123" in repr_str
        assert "scale_up" in repr_str
    
    def test_scaling_event_table_name(self):
        """Test that ScalingEvent uses correct table name and schema"""
        assert ScalingEvent.__tablename__ == "scaling_events"
        assert ScalingEvent.__table_args__[-1]["schema"] == "platform_shared"
