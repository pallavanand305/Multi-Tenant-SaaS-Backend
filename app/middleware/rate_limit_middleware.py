"""
Rate Limiting Middleware

Enforces per-tenant rate limits using Redis-backed token bucket algorithm.

Requirements: 6.1, 6.2, 6.4
"""

from typing import Optional
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import structlog
import redis.asyncio as redis

from app.config import settings

logger = structlog.get_logger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware for enforcing per-tenant rate limits.
    
    This middleware:
    1. Retrieves tenant_id from request.state
    2. Checks rate limit using Redis token bucket algorithm
    3. Returns HTTP 429 if limit exceeded with Retry-After header
    4. Allows request to proceed if within limit
    
    Rate limits are configured per tenant tier:
    - Free: 100 requests per 60 seconds
    - Pro: 1000 requests per 60 seconds
    - Enterprise: 10000 requests per 60 seconds
    
    Requirements:
    - 6.1: Enforce configurable request limits per tenant per time window
    - 6.2: Reject requests exceeding rate limit
    - 6.4: Return HTTP 429 with retry-after information
    """
    
    # Endpoints that don't require rate limiting
    PUBLIC_PATHS = {
        "/",
        "/health",
        "/docs",
        "/redoc",
        "/openapi.json",
    }
    
    def __init__(
        self,
        app,
        redis_client: Optional[redis.Redis] = None
    ):
        """
        Initialize rate limiting middleware.
        
        Args:
            app: FastAPI application instance
            redis_client: Redis client instance (creates default if not provided)
        """
        super().__init__(app)
        
        # Initialize Redis client for rate limiting
        if redis_client is None:
            redis_url = settings.REDIS_URL.replace("/0", f"/{settings.REDIS_RATE_LIMIT_DB}")
            self.redis = redis.from_url(
                redis_url,
                encoding="utf-8",
                decode_responses=True
            )
        else:
            self.redis = redis_client
        
        # Rate limit configurations by tier
        self.rate_limits = {
            "free": {
                "max_requests": settings.RATE_LIMIT_FREE_TIER,
                "window": settings.RATE_LIMIT_WINDOW_SECONDS
            },
            "pro": {
                "max_requests": settings.RATE_LIMIT_PRO_TIER,
                "window": settings.RATE_LIMIT_WINDOW_SECONDS
            },
            "enterprise": {
                "max_requests": settings.RATE_LIMIT_ENTERPRISE_TIER,
                "window": settings.RATE_LIMIT_WINDOW_SECONDS
            }
        }
        
        logger.info("RateLimitMiddleware initialized", rate_limits=self.rate_limits)
    
    async def dispatch(self, request: Request, call_next):
        """
        Process request and check rate limits.
        
        Args:
            request: Incoming HTTP request
            call_next: Next middleware/handler in chain
            
        Returns:
            HTTP response (429 if rate limited, otherwise continues)
        """
        # Skip rate limiting for public paths
        if request.url.path in self.PUBLIC_PATHS:
            return await call_next(request)
        
        # Skip for OPTIONS requests
        if request.method == "OPTIONS":
            return await call_next(request)
        
        # Get tenant_id from request state
        tenant_id = getattr(request.state, "tenant_id", None)
        
        if not tenant_id:
            # If no tenant_id, skip rate limiting (should be caught by auth middleware)
            logger.warning(
                "Rate limiting skipped - no tenant_id in request state",
                path=request.url.path
            )
            return await call_next(request)
        
        try:
            # Check rate limit
            result = await self._check_rate_limit(tenant_id)
            
            if not result["allowed"]:
                logger.warning(
                    "Rate limit exceeded",
                    tenant_id=tenant_id,
                    path=request.url.path,
                    retry_after=result["retry_after"]
                )
                
                return JSONResponse(
                    status_code=429,
                    headers={
                        "Retry-After": str(result["retry_after"]),
                        "X-RateLimit-Limit": str(result["limit"]),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(result["retry_after"])
                    },
                    content={
                        "error": {
                            "code": "RATE_LIMIT_EXCEEDED",
                            "message": f"Rate limit exceeded. Retry after {result['retry_after']} seconds.",
                            "details": {
                                "limit": result["limit"],
                                "window": result["window"],
                                "retry_after": result["retry_after"]
                            }
                        }
                    }
                )
            
            # Add rate limit headers to response
            response = await call_next(request)
            response.headers["X-RateLimit-Limit"] = str(result["limit"])
            response.headers["X-RateLimit-Remaining"] = str(result["remaining"])
            response.headers["X-RateLimit-Reset"] = str(result["window"])
            
            return response
        
        except Exception as e:
            logger.error(
                "Error checking rate limit",
                tenant_id=tenant_id,
                error=str(e),
                path=request.url.path,
                exc_info=True
            )
            # On error, allow request to proceed (fail open)
            return await call_next(request)
    
    async def _check_rate_limit(self, tenant_id: str) -> dict:
        """
        Check rate limit for tenant using Redis token bucket algorithm.
        
        Args:
            tenant_id: Tenant identifier
            
        Returns:
            Dictionary with:
            - allowed: bool - whether request is allowed
            - remaining: int - remaining requests in window
            - retry_after: int - seconds until reset (if not allowed)
            - limit: int - max requests per window
            - window: int - window duration in seconds
        """
        # Get tenant tier (default to free)
        # In production, this would be fetched from database
        tier = await self._get_tenant_tier(tenant_id)
        limit_config = self.rate_limits.get(tier, self.rate_limits["free"])
        
        max_requests = limit_config["max_requests"]
        window = limit_config["window"]
        
        # Redis key for rate limiting
        key = f"rate_limit:{tenant_id}"
        
        try:
            # Get current count
            current = await self.redis.get(key)
            
            if current is None:
                # First request in window
                await self.redis.setex(key, window, 1)
                return {
                    "allowed": True,
                    "remaining": max_requests - 1,
                    "retry_after": 0,
                    "limit": max_requests,
                    "window": window
                }
            
            current_count = int(current)
            
            if current_count >= max_requests:
                # Rate limit exceeded
                ttl = await self.redis.ttl(key)
                return {
                    "allowed": False,
                    "remaining": 0,
                    "retry_after": ttl if ttl > 0 else window,
                    "limit": max_requests,
                    "window": window
                }
            
            # Increment counter
            await self.redis.incr(key)
            
            return {
                "allowed": True,
                "remaining": max_requests - current_count - 1,
                "retry_after": 0,
                "limit": max_requests,
                "window": window
            }
        
        except redis.RedisError as e:
            logger.error(
                "Redis error in rate limiting",
                tenant_id=tenant_id,
                error=str(e)
            )
            # On Redis error, allow request (fail open)
            return {
                "allowed": True,
                "remaining": max_requests,
                "retry_after": 0,
                "limit": max_requests,
                "window": window
            }
    
    async def _get_tenant_tier(self, tenant_id: str) -> str:
        """
        Get tenant tier from cache or database.
        
        Args:
            tenant_id: Tenant identifier
            
        Returns:
            Tier name (free, pro, enterprise)
        """
        # Check Redis cache first
        cache_key = f"tenant_tier:{tenant_id}"
        
        try:
            cached_tier = await self.redis.get(cache_key)
            if cached_tier:
                return cached_tier
        except redis.RedisError:
            pass
        
        # Default to free tier if not found
        # In production, this would query the database
        # For now, we'll use a simple heuristic or default
        default_tier = "free"
        
        # Cache the tier for 5 minutes
        try:
            await self.redis.setex(cache_key, 300, default_tier)
        except redis.RedisError:
            pass
        
        return default_tier
    
    async def close(self):
        """Close Redis connection"""
        await self.redis.close()
