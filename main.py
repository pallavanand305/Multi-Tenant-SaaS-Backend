"""
Multi-Tenant SaaS Platform - Main Application Entry Point

This module initializes the FastAPI application with all middleware,
routes, and configuration for the multi-tenant SaaS platform.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import structlog

from app.config import settings

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown events"""
    # Startup
    logger.info("application_starting", environment=settings.ENVIRONMENT)
    
    # TODO: Initialize database connections
    # TODO: Initialize Redis connections
    # TODO: Verify Celery connectivity
    
    logger.info("application_started")
    
    yield
    
    # Shutdown
    logger.info("application_shutting_down")
    
    # TODO: Close database connections
    # TODO: Close Redis connections
    
    logger.info("application_stopped")


# Create FastAPI application
app = FastAPI(
    title="Multi-Tenant SaaS Platform API",
    description="Enterprise-grade multi-tenant backend with tenant isolation, authentication, and usage metering",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
    openapi_tags=[
        {"name": "Authentication", "description": "JWT and API key authentication"},
        {"name": "Tenants", "description": "Tenant management and onboarding"},
        {"name": "Resources", "description": "Tenant-specific resource operations"},
        {"name": "Jobs", "description": "Background job management"},
        {"name": "Usage", "description": "Usage metrics and metering"},
        {"name": "Health", "description": "System health and monitoring"}
    ]
)

# Configure CORS
if settings.CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS.split(","),
        allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# TODO: Add middleware in correct order:
# 1. Logging middleware
# 2. Authentication middleware
# 3. Tenant context middleware
# 4. Rate limiting middleware
# 5. Metering middleware

# TODO: Register API routers
# app.include_router(auth_router)
# app.include_router(tenants_router)
# app.include_router(resources_router)
# app.include_router(jobs_router)
# app.include_router(usage_router)
# app.include_router(health_router)


@app.get("/")
async def root():
    """Root endpoint - API information"""
    return {
        "name": "Multi-Tenant SaaS Platform API",
        "version": "1.0.0",
        "environment": settings.ENVIRONMENT,
        "docs": "/docs",
        "health": "/health"
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    )
