"""
Unit tests for application configuration
"""

import pytest
from app.config import settings


def test_settings_loaded():
    """Test that settings are loaded correctly"""
    assert settings is not None
    assert settings.ENVIRONMENT in ["development", "staging", "production"]


def test_database_url_configured():
    """Test that database URL is configured"""
    assert settings.DATABASE_URL is not None
    assert "postgresql" in settings.DATABASE_URL


def test_redis_url_configured():
    """Test that Redis URL is configured"""
    assert settings.REDIS_URL is not None
    assert "redis" in settings.REDIS_URL


def test_jwt_configuration():
    """Test that JWT configuration is present"""
    assert settings.JWT_ALGORITHM == "RS256"
    assert settings.JWT_EXPIRATION_SECONDS > 0
    assert settings.JWT_PRIVATE_KEY_PATH is not None
    assert settings.JWT_PUBLIC_KEY_PATH is not None


def test_rate_limit_tiers():
    """Test that rate limit tiers are configured"""
    assert settings.RATE_LIMIT_FREE_TIER > 0
    assert settings.RATE_LIMIT_PRO_TIER > settings.RATE_LIMIT_FREE_TIER
    assert settings.RATE_LIMIT_ENTERPRISE_TIER > settings.RATE_LIMIT_PRO_TIER


def test_autoscaling_thresholds():
    """Test that autoscaling thresholds are configured"""
    assert settings.AUTOSCALE_REQUESTS_PER_MIN_HIGH > settings.AUTOSCALE_REQUESTS_PER_MIN_LOW
    assert settings.AUTOSCALE_RESPONSE_TIME_HIGH_MS > settings.AUTOSCALE_RESPONSE_TIME_LOW_MS
    assert settings.AUTOSCALE_COOLDOWN_SECONDS > 0
