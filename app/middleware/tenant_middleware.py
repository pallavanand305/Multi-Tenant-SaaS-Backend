"""
Tenant Context Middleware

Establishes database session with tenant-specific search_path for request isolation.

Requirements: 1.1, 1.2, 1.4
"""

from typing import Optional
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import structlog

from app.tenant_router import TenantRouter
from app.database import engine
from app.auth.api_key_manager import APIKeyManager, APIKeyError

logger = structlog.get_logger(__name__)


class TenantContextMiddleware(BaseHTTPMiddleware):
    """
    Middleware for establishing tenant-specific database context.
    
    This middleware:
    1. Retrieves tenant_id from request.state (set by AuthenticationMiddleware)
    2. Validates tenant exists and is active
    3. Creates database session with tenant-specific search_path
    4. Validates pending API keys (if present)
    5. Stores session in request.state.db_session
    6. Ensures session is closed after request completes
    
    Requirements:
    - 1.1: Identify tenant from request context
    - 1.2: Route database operations to correct tenant schema
    - 1.4: Validate tenant context matches connection target
    """
    
    # Endpoints that don't require tenant context
    PUBLIC_PATHS = {
        "/",
        "/health",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/auth/login",
        "/tenants",  # Tenant onboarding endpoint
    }
    
    def __init__(
        self,
        app,
        tenant_router: Optional[TenantRouter] = None,
        api_key_manager: Optional[APIKeyManager] = None
    ):
        """
        Initialize tenant context middleware.
        
        Args:
            app: FastAPI application instance
            tenant_router: TenantRouter instance (creates default if not provided)
            api_key_manager: APIKeyManager instance (creates default if not provided)
        """
        super().__init__(app)
        self.tenant_router = tenant_router or TenantRouter(engine)
        self.api_key_manager = api_key_manager or APIKeyManager()
        logger.info("TenantContextMiddleware initialized")
    
    async def dispatch(self, request: Request, call_next):
        """
        Process request and establish tenant context.
        
        Args:
            request: Incoming HTTP request
            call_next: Next middleware/handler in chain
            
        Returns:
            HTTP response
        """
        # Skip tenant context for public paths
        if request.url.path in self.PUBLIC_PATHS:
            return await call_next(request)
        
        # Skip for OPTIONS requests
        if request.method == "OPTIONS":
            return await call_next(request)
        
        # Get tenant_id from request state (set by AuthenticationMiddleware)
        tenant_id = getattr(request.state, "tenant_id", None)
        
        if not tenant_id:
            logger.error(
                "Tenant ID not found in request state",
                path=request.url.path
            )
            return JSONResponse(
                status_code=401,
                content={
                    "error": {
                        "code": "MISSING_TENANT_CONTEXT",
                        "message": "Tenant context not established. Authentication may have failed."
                    }
                }
            )
        
        try:
            # Validate tenant exists and is active
            is_valid = await self.tenant_router.validate_tenant(tenant_id)
            
            if not is_valid:
                logger.warning(
                    "Invalid or inactive tenant",
                    tenant_id=tenant_id,
                    path=request.url.path
                )
                return JSONResponse(
                    status_code=404,
                    content={
                        "error": {
                            "code": "TENANT_NOT_FOUND",
                            "message": f"Tenant '{tenant_id}' not found or inactive"
                        }
                    }
                )
            
            # Get database session with tenant schema
            session = await self.tenant_router.get_session(tenant_id)
            request.state.db_session = session
            
            # Validate pending API key if present
            if hasattr(request.state, "pending_api_key"):
                await self._validate_pending_api_key(request, session)
            
            logger.debug(
                "Tenant context established",
                tenant_id=tenant_id,
                path=request.url.path
            )
            
            try:
                # Continue to next middleware
                response = await call_next(request)
                return response
            finally:
                # Always close the database session
                await session.close()
                logger.debug(
                    "Database session closed",
                    tenant_id=tenant_id
                )
        
        except ValueError as e:
            logger.error(
                "Invalid tenant ID format",
                tenant_id=tenant_id,
                error=str(e),
                path=request.url.path
            )
            return JSONResponse(
                status_code=400,
                content={
                    "error": {
                        "code": "INVALID_TENANT_ID",
                        "message": str(e)
                    }
                }
            )
        
        except Exception as e:
            logger.error(
                "Error establishing tenant context",
                tenant_id=tenant_id,
                error=str(e),
                path=request.url.path,
                exc_info=True
            )
            
            # Close session if it was created
            if hasattr(request.state, "db_session"):
                try:
                    await request.state.db_session.close()
                except Exception:
                    pass
            
            return JSONResponse(
                status_code=500,
                content={
                    "error": {
                        "code": "TENANT_CONTEXT_ERROR",
                        "message": "Failed to establish tenant context"
                    }
                }
            )
    
    async def _validate_pending_api_key(self, request: Request, session):
        """
        Validate API key that was deferred from authentication middleware.
        
        Args:
            request: HTTP request with pending_api_key in state
            session: Database session with tenant context
            
        Raises:
            APIKeyError: If API key validation fails
        """
        api_key = request.state.pending_api_key
        tenant_id = request.state.pending_tenant_id
        
        try:
            # Validate API key with database session
            payload = await self.api_key_manager.validate_api_key(
                db=session,
                tenant_id=tenant_id,
                key=api_key
            )
            
            # Update request state with validated information
            request.state.user_id = f"api_key_{payload.key_id}"
            request.state.role = payload.role
            request.state.api_key_id = payload.key_id
            
            logger.info(
                "API key validated",
                tenant_id=tenant_id,
                key_id=str(payload.key_id),
                role=payload.role,
                name=payload.name
            )
            
            # Clean up pending state
            delattr(request.state, "pending_api_key")
            delattr(request.state, "pending_tenant_id")
            
        except APIKeyError as e:
            logger.warning(
                "API key validation failed",
                tenant_id=tenant_id,
                error=e.message,
                code=e.code
            )
            raise
