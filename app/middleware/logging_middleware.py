"""
Logging Middleware

Structured logging with tenant context and correlation IDs for request tracing.

Requirements: 13.1, 13.5
"""

import time
import uuid
from typing import Optional
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
import structlog

logger = structlog.get_logger(__name__)


class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for structured logging with tenant context.
    
    This middleware:
    1. Generates correlation ID for request tracing
    2. Binds tenant context to all logs in request scope
    3. Logs request start and completion
    4. Logs request duration and status
    5. Includes correlation ID in response headers
    
    All logs include:
    - correlation_id: Unique identifier for request tracing
    - tenant_id: Tenant identifier (if authenticated)
    - user_id: User identifier (if authenticated)
    - method: HTTP method
    - path: Request path
    - status_code: Response status code
    - duration_ms: Request processing duration
    
    Requirements:
    - 13.1: Log all API requests with tenant context, timestamp, endpoint, and response status
    - 13.5: Include correlation identifiers to trace requests across components
    """
    
    def __init__(self, app):
        """
        Initialize logging middleware.
        
        Args:
            app: FastAPI application instance
        """
        super().__init__(app)
        logger.info("LoggingMiddleware initialized")
    
    async def dispatch(self, request: Request, call_next):
        """
        Process request with structured logging.
        
        Args:
            request: Incoming HTTP request
            call_next: Next middleware/handler in chain
            
        Returns:
            HTTP response
        """
        # Generate correlation ID
        correlation_id = str(uuid.uuid4())
        request.state.correlation_id = correlation_id
        
        # Get tenant context (if available)
        tenant_id = getattr(request.state, "tenant_id", None)
        user_id = getattr(request.state, "user_id", None)
        auth_method = getattr(request.state, "auth_method", None)
        
        # Bind context for all logs in this request
        structlog.contextvars.bind_contextvars(
            correlation_id=correlation_id,
            tenant_id=tenant_id,
            user_id=user_id,
            auth_method=auth_method,
            method=request.method,
            path=request.url.path,
            client_ip=self._get_client_ip(request)
        )
        
        # Record start time
        start_time = time.time()
        
        # Log request start
        logger.info(
            "api_request_started",
            query_params=dict(request.query_params) if request.query_params else None,
            user_agent=request.headers.get("user-agent")
        )
        
        try:
            # Process request
            response = await call_next(request)
            
            # Calculate duration
            duration_ms = (time.time() - start_time) * 1000
            
            # Log request completion
            logger.info(
                "api_request_completed",
                status_code=response.status_code,
                duration_ms=duration_ms
            )
            
            # Add correlation ID to response headers
            response.headers["X-Correlation-ID"] = correlation_id
            
            return response
        
        except Exception as e:
            # Calculate duration
            duration_ms = (time.time() - start_time) * 1000
            
            # Log request failure
            logger.error(
                "api_request_failed",
                error=str(e),
                error_type=type(e).__name__,
                duration_ms=duration_ms,
                exc_info=True
            )
            
            raise
        
        finally:
            # Clear context variables
            structlog.contextvars.clear_contextvars()
    
    def _get_client_ip(self, request: Request) -> Optional[str]:
        """
        Extract client IP address from request.
        
        Checks X-Forwarded-For header first (for proxied requests),
        then falls back to direct client address.
        
        Args:
            request: HTTP request
            
        Returns:
            Client IP address or None
        """
        # Check X-Forwarded-For header (for requests through load balancer/proxy)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            # X-Forwarded-For can contain multiple IPs, take the first one
            return forwarded_for.split(",")[0].strip()
        
        # Check X-Real-IP header
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        # Fall back to direct client address
        if request.client:
            return request.client.host
        
        return None
