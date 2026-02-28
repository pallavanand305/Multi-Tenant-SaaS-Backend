"""
Metering Middleware

Records usage metrics for each API request (count, compute time, data transfer).

Requirements: 5.1, 5.2
"""

import time
from typing import Optional
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
import structlog

logger = structlog.get_logger(__name__)


class MeteringMiddleware(BaseHTTPMiddleware):
    """
    Middleware for recording usage metrics.
    
    This middleware:
    1. Records start time of request
    2. Measures request and response sizes
    3. Calculates compute time (request duration)
    4. Buffers metrics for batch writing
    5. Records metrics with tenant context
    
    Metrics tracked:
    - api_request: Count of API requests
    - compute_time: Request processing duration in milliseconds
    - data_transfer: Total bytes transferred (request + response)
    
    Requirements:
    - 5.1: Record usage metrics for each API request
    - 5.2: Track API request count, compute time, and data transfer volume
    """
    
    # Endpoints that don't require metering
    PUBLIC_PATHS = {
        "/",
        "/health",
        "/docs",
        "/redoc",
        "/openapi.json",
    }
    
    def __init__(self, app):
        """
        Initialize metering middleware.
        
        Args:
            app: FastAPI application instance
        """
        super().__init__(app)
        
        # In-memory buffer for metrics (will be flushed periodically)
        self.metrics_buffer = []
        self.buffer_size = 100  # Flush after 100 metrics
        
        logger.info("MeteringMiddleware initialized")
    
    async def dispatch(self, request: Request, call_next):
        """
        Process request and record metrics.
        
        Args:
            request: Incoming HTTP request
            call_next: Next middleware/handler in chain
            
        Returns:
            HTTP response
        """
        # Skip metering for public paths
        if request.url.path in self.PUBLIC_PATHS:
            return await call_next(request)
        
        # Skip for OPTIONS requests
        if request.method == "OPTIONS":
            return await call_next(request)
        
        # Get tenant_id from request state
        tenant_id = getattr(request.state, "tenant_id", None)
        
        if not tenant_id:
            # If no tenant_id, skip metering
            return await call_next(request)
        
        # Record start time
        start_time = time.time()
        
        # Get request size
        request_size = await self._get_request_size(request)
        
        try:
            # Process request
            response = await call_next(request)
            
            # Calculate metrics
            duration_ms = (time.time() - start_time) * 1000
            response_size = self._get_response_size(response)
            total_transfer = request_size + response_size
            
            # Record metrics
            await self._record_metrics(
                tenant_id=tenant_id,
                path=request.url.path,
                method=request.method,
                status_code=response.status_code,
                duration_ms=duration_ms,
                request_size=request_size,
                response_size=response_size,
                total_transfer=total_transfer
            )
            
            # Add metering headers to response
            response.headers["X-Compute-Time-Ms"] = str(int(duration_ms))
            response.headers["X-Request-Size"] = str(request_size)
            response.headers["X-Response-Size"] = str(response_size)
            
            return response
        
        except Exception as e:
            # Record error metric
            duration_ms = (time.time() - start_time) * 1000
            
            await self._record_metrics(
                tenant_id=tenant_id,
                path=request.url.path,
                method=request.method,
                status_code=500,
                duration_ms=duration_ms,
                request_size=request_size,
                response_size=0,
                total_transfer=request_size,
                error=str(e)
            )
            
            raise
    
    async def _get_request_size(self, request: Request) -> int:
        """
        Calculate request body size in bytes.
        
        Args:
            request: HTTP request
            
        Returns:
            Request size in bytes
        """
        try:
            # Get content-length header if available
            content_length = request.headers.get("content-length")
            if content_length:
                return int(content_length)
            
            # If no content-length, estimate from body
            # Note: This consumes the body, so we need to be careful
            # For now, we'll just use content-length or default to 0
            return 0
        
        except Exception as e:
            logger.warning(
                "Error calculating request size",
                error=str(e)
            )
            return 0
    
    def _get_response_size(self, response) -> int:
        """
        Calculate response body size in bytes.
        
        Args:
            response: HTTP response
            
        Returns:
            Response size in bytes
        """
        try:
            # Get content-length header if available
            content_length = response.headers.get("content-length")
            if content_length:
                return int(content_length)
            
            # Estimate from body if available
            if hasattr(response, "body"):
                return len(response.body)
            
            return 0
        
        except Exception as e:
            logger.warning(
                "Error calculating response size",
                error=str(e)
            )
            return 0
    
    async def _record_metrics(
        self,
        tenant_id: str,
        path: str,
        method: str,
        status_code: int,
        duration_ms: float,
        request_size: int,
        response_size: int,
        total_transfer: int,
        error: Optional[str] = None
    ):
        """
        Record usage metrics for the request.
        
        Args:
            tenant_id: Tenant identifier
            path: Request path
            method: HTTP method
            status_code: Response status code
            duration_ms: Request duration in milliseconds
            request_size: Request body size in bytes
            response_size: Response body size in bytes
            total_transfer: Total data transfer in bytes
            error: Optional error message
        """
        from datetime import datetime
        
        timestamp = datetime.utcnow()
        
        # Create metric records
        metrics = [
            {
                "tenant_id": tenant_id,
                "metric_type": "api_request",
                "value": 1,
                "timestamp": timestamp,
                "metadata": {
                    "path": path,
                    "method": method,
                    "status_code": status_code,
                    "error": error
                }
            },
            {
                "tenant_id": tenant_id,
                "metric_type": "compute_time",
                "value": duration_ms,
                "timestamp": timestamp,
                "metadata": {
                    "path": path,
                    "method": method,
                    "status_code": status_code
                }
            },
            {
                "tenant_id": tenant_id,
                "metric_type": "data_transfer",
                "value": total_transfer,
                "timestamp": timestamp,
                "metadata": {
                    "path": path,
                    "method": method,
                    "request_size": request_size,
                    "response_size": response_size
                }
            }
        ]
        
        # Add to buffer
        self.metrics_buffer.extend(metrics)
        
        logger.debug(
            "Metrics recorded",
            tenant_id=tenant_id,
            path=path,
            duration_ms=duration_ms,
            total_transfer=total_transfer,
            buffer_size=len(self.metrics_buffer)
        )
        
        # Flush if buffer is full
        if len(self.metrics_buffer) >= self.buffer_size:
            await self._flush_metrics()
    
    async def _flush_metrics(self):
        """
        Flush buffered metrics to storage.
        
        In production, this would write to TimescaleDB or a metrics service.
        For now, we'll just log the metrics.
        """
        if not self.metrics_buffer:
            return
        
        metrics_count = len(self.metrics_buffer)
        
        logger.info(
            "Flushing metrics buffer",
            count=metrics_count
        )
        
        # TODO: Write metrics to TimescaleDB
        # For now, we'll just clear the buffer
        # In production, this would be:
        # await metering_service.flush(self.metrics_buffer)
        
        self.metrics_buffer.clear()
        
        logger.debug(
            "Metrics buffer flushed",
            count=metrics_count
        )
    
    async def close(self):
        """Flush remaining metrics on shutdown"""
        await self._flush_metrics()
