"""
Application Configuration

Loads configuration from environment variables using Pydantic Settings.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True
    )
    
    # Application
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"
    
    # API Configuration
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_WORKERS: int = 4
    
    # Database
    DATABASE_URL: str = "postgresql+asyncpg://postgres:password@localhost:5432/saas_platform"
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_RATE_LIMIT_DB: int = 1
    
    # JWT Configuration
    JWT_ALGORITHM: str = "RS256"
    JWT_EXPIRATION_SECONDS: int = 3600
    JWT_PRIVATE_KEY_PATH: str = "keys/jwt_private.pem"
    JWT_PUBLIC_KEY_PATH: str = "keys/jwt_public.pem"
    
    # Celery
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"
    CELERY_TASK_TIME_LIMIT: int = 3600
    CELERY_TASK_SOFT_TIME_LIMIT: int = 3300
    
    # AWS Configuration
    AWS_REGION: str = "us-east-1"
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None
    
    # Rate Limiting
    RATE_LIMIT_FREE_TIER: int = 100
    RATE_LIMIT_PRO_TIER: int = 1000
    RATE_LIMIT_ENTERPRISE_TIER: int = 10000
    RATE_LIMIT_WINDOW_SECONDS: int = 60
    
    # Autoscaling Thresholds
    AUTOSCALE_REQUESTS_PER_MIN_HIGH: int = 1000
    AUTOSCALE_REQUESTS_PER_MIN_LOW: int = 100
    AUTOSCALE_RESPONSE_TIME_HIGH_MS: int = 500
    AUTOSCALE_RESPONSE_TIME_LOW_MS: int = 100
    AUTOSCALE_COOLDOWN_SECONDS: int = 300
    
    # Monitoring
    PROMETHEUS_ENABLED: bool = True
    CLOUDWATCH_ENABLED: bool = False
    
    # CORS
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:8080"
    CORS_ALLOW_CREDENTIALS: bool = True


# Global settings instance
settings = Settings()
