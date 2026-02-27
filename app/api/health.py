"""
Health Check Endpoints
"""

from fastapi import APIRouter
from pydantic import BaseModel
from datetime import datetime
import time

from app.database import db_manager
from app.config import settings


router = APIRouter(tags=["Health"])


class HealthResponse(BaseModel):
    status: str
    timestamp: str
    environment: str
    checks: dict
    response_time_ms: float


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Comprehensive health check"""
    start_time = time.time()
    
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "environment": settings.ENVIRONMENT,
        "checks": {}
    }
    
    # Database check
    try:
        db_healthy = await db_manager.health_check()
        health_status["checks"]["database"] = {
            "status": "healthy" if db_healthy else "unhealthy"
        }
        if not db_healthy:
            health_status["status"] = "degraded"
    except Exception as e:
        health_status["checks"]["database"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        health_status["status"] = "degraded"
    
    response_time = (time.time() - start_time) * 1000
    health_status["response_time_ms"] = response_time
    
    return HealthResponse(**health_status)
