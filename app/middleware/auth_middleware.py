"""
Authentication Middleware

Extracts and validates JWT tokens or API keys from requests, setting request state
with tenant context information.

Requirements: 2.1, 2.2, 4.3
"""

from typing import Optional
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import structlog

from app.auth.auth_service import AuthService, TenantContext
from app.auth.jwt_handler import AuthenticationError
from app.auth.api_key_manager import APIKeyError

logger = structlog.get_logger(__name__)


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """
    Middleware for extracting and validating authentication credentials.
    
    This middleware:
    1. Extracts JWT tokens from Authorization header (Bearer scheme)
    2. Extracts API keys from X-API-Key header
    3. Validates credentials using AuthService
    4. Sets request.state with tenant context (tenant_id, user_id, role)
    5. Handles authentication errors with appropriate HTTP responses
    
    Public endpoints (health checks, docs) bypass authentication.
    
    Requirements:
    - 2.1: Validate JWT tokens
    - 2.2: Validate token signature and expiration
    - 4.3: Validate API keys
    """
    
    # Endpoints that don't require authentication
    PUBLIC_PATHS = {
        "/",
        "/health",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/auth/login",
        "/tenants",  # Tenant onboarding endpoint
    }
    
    def __init__(self, app, auth_service: Optional[AuthService] = None):
        """
        Initialize authentication middleware.
        
        Args:
            app: FastAPI application instance
            auth_service: AuthService instance (creates default if not provided)
        """
        super().__init__(app)
        self.auth_service = auth_service or AuthService()
        logger.info("AuthenticationMiddleware initialized")
    
    async def dispatch(self, request: Request, call_next):
        """
        Process request and validate authentication.
        
        Args:
            request: Incoming HTTP request
            call_next: Next middleware/handler in chain
            
        Returns:
            HTTP response
        """
        # Skip authentication for public paths
        if request.url.path in self.PUBLIC_PATHS:
            return await call_next(request)
        
        # Skip authentication for OPTIONS requests (CORS preflight)
        if request.method == "OPTIONS":
            return await call_next(request)
        
        try:
            # Extract credentials from request
            tenant_context = await self._extract_and_validate_credentials(request)
            
            if tenant_context is None:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={
                        "error": {
                            "code": "MISSING_CREDENTIALS",
                            "message": "Authentication required. Provide JWT token or API key."
                        }
                    }
                )
            
            # Set request state with tenant context
            request.state.tenant_id = tenant_context.tenant_id
            request.state.user_id = tenant_context.user_id
            request.state.role = tenant_context.role
            request.state.auth_method = tenant_context.auth_method
            request.state.api_key_id = tenant_context.api_key_id
            
            logger.debug(
                "Authentication successful",
                tenant_id=tenant_context.tenant_id,
                user_id=tenant_context.user_id,
                role=tenant_context.role,
                method=tenant_context.auth_method,
                path=request.url.path
            )
            
            # Continue to next middleware
            response = await call_next(request)
            return response
            
        except AuthenticationError as e:
            logger.warning(
                "Authentication failed",
                error=e.message,
                code=e.code,
                path=request.url.path
            )
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "error": {
                        "code": e.code,
                        "message": e.message
                    }
                }
            )
        
        except APIKeyError as e:
            logger.warning(
                "API key authentication failed",
                error=e.message,
                code=e.code,
                path=request.url.path
            )
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "error": {
                        "code": e.code,
                        "message": e.message
                    }
                }
            )
        
        except Exception as e:
            logger.error(
                "Unexpected error in authentication middleware",
                error=str(e),
                path=request.url.path,
                exc_info=True
            )
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "error": {
                        "code": "INTERNAL_ERROR",
                        "message": "An unexpected error occurred during authentication"
                    }
                }
            )
    
    async def _extract_and_validate_credentials(
        self,
        request: Request
    ) -> Optional[TenantContext]:
        """
        Extract and validate credentials from request headers.
        
        Checks for:
        1. Authorization header with Bearer token (JWT)
        2. X-API-Key header with API key
        
        Args:
            request: HTTP request
            
        Returns:
            TenantContext if credentials are valid, None if no credentials provided
            
        Raises:
            AuthenticationError: If JWT validation fails
            APIKeyError: If API key validation fails
        """
        # Check for JWT token in Authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]  # Remove "Bearer " prefix
            return self.auth_service.extract_tenant_context_from_jwt(token)
        
        # Check for API key in X-API-Key header
        api_key = request.headers.get("X-API-Key")
        if api_key:
            # For API key authentication, we need tenant_id
            # Extract from path or query parameter
            tenant_id = self._extract_tenant_id_from_request(request)
            
            if not tenant_id:
                raise APIKeyError(
                    "MISSING_TENANT_ID",
                    "Tenant ID required for API key authentication"
                )
            
            # API key validation requires database session
            # We'll need to get the session from tenant router
            # For now, we'll defer this to the tenant context middleware
            # Store the API key in request state for later validation
            request.state.pending_api_key = api_key
            request.state.pending_tenant_id = tenant_id
            
            # Return a placeholder context that will be validated in tenant middleware
            return TenantContext(
                tenant_id=tenant_id,
                user_id="api_key_pending",
                role="pending",
                auth_method="api_key"
            )
        
        # No credentials provided
        return None
    
    def _extract_tenant_id_from_request(self, request: Request) -> Optional[str]:
        """
        Extract tenant_id from request path or query parameters.
        
        Looks for tenant_id in:
        1. Query parameter: ?tenant_id=xxx
        2. Path parameter: /api/v1/tenants/{tenant_id}/...
        
        Args:
            request: HTTP request
            
        Returns:
            Tenant ID if found, None otherwise
        """
        # Check query parameters
        tenant_id = request.query_params.get("tenant_id")
        if tenant_id:
            return tenant_id
        
        # Check path parameters (if using path-based tenant routing)
        # Example: /api/v1/tenants/tenant_abc/resources
        path_parts = request.url.path.split("/")
        if "tenants" in path_parts:
            try:
                tenant_index = path_parts.index("tenants")
                if tenant_index + 1 < len(path_parts):
                    return path_parts[tenant_index + 1]
            except (ValueError, IndexError):
                pass
        
        return None
