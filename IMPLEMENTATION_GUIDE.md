# Multi-Tenant FastAPI SaaS Platform - Implementation Guide

This guide provides detailed instructions, code templates, and best practices for completing the remaining features of the multi-tenant SaaS platform.

---

## Table of Contents

1. [Quick Reference](#quick-reference)
2. [Phase 1: Core MVP](#phase-1-core-mvp)
3. [Phase 2: Infrastructure](#phase-2-infrastructure)
4. [Phase 3: Polish & Documentation](#phase-3-polish--documentation)
5. [Testing Strategy](#testing-strategy)
6. [Deployment Guide](#deployment-guide)

---

## Quick Reference

### What's Already Implemented ✅

- Project structure and configuration
- Database models (shared and tenant-specific)
- Tenant routing with schema isolation
- JWT authentication (RS256)
- API key management
- Comprehensive test suite (88 tests)

### What Needs Implementation 🚧

- AuthService integration
- RBAC engine
- All middleware
- Core services (rate limiting, metering, background jobs, autoscaling)
- API endpoints
- Error handling and logging
- Database migrations
- Infrastructure (Terraform, CI/CD)
- Documentation

---

## Phase 1: Core MVP

### Task 3.3: Implement AuthService Class

**File:** `app/auth/auth_service.py`

```python
"""
Authentication Service

Integrates JWT and API key authentication, providing a unified interface
for credential verification and tenant context extraction.
"""

from typing import Optional, Union
from uuid import UUID
import structlog

from sqlalchemy.ext.asyncio import AsyncSession
from passlib.context import CryptContext

from app.auth.jwt_handler import JWTHandler, TokenPayload, AuthenticationError
from app.auth.api_key_manager import APIKeyManager, APIKeyPayload, APIKeyError
from app.models.tenant import User


logger = structlog.get_logger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthService:
    """
    Unified authentication service.
    
    Provides methods for:
    - User login with password verification
    - JWT token generation
    - API key validation
    - Tenant context extraction from credentials
    """
    
    def __init__(self):
        self.jwt_handler = JWTHandler()
        self.api_key_manager = APIKeyManager()
        logger.info("auth_service_initialized")
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        return pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    async def authenticate_user(
        self,
        db: AsyncSession,
        email: str,
        password: str
    ) -> Optional[User]:
        """
        Authenticate user with email and password.
        
        Args:
            db: Database session (must be set to tenant schema)
            email: User email
            password: Plain text password
        
        Returns:
            User object if authentication succeeds, None otherwise
        """
        from sqlalchemy import select
        
        stmt = select(User).where(User.email == email)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        
        if user is None:
            logger.warning("user_not_found", email=email)
            return None
        
        if not self.verify_password(password, user.password_hash):
            logger.warning("invalid_password", email=email)
            return None
        
        logger.info("user_authenticated", user_id=str(user.id), email=email)
        return user
    
    async def login(
        self,
        db: AsyncSession,
        tenant_id: str,
        email: str,
        password: str
    ) -> Optional[str]:
        """
        Login user and generate JWT token.
        
        Args:
            db: Database session (must be set to tenant schema)
            tenant_id: Tenant identifier
            email: User email
            password: Plain text password
        
        Returns:
            JWT token if login succeeds, None otherwise
        """
        user = await self.authenticate_user(db, email, password)
        
        if user is None:
            return None
        
        # Generate JWT token
        token = self.jwt_handler.generate_jwt(
            user_id=str(user.id),
            tenant_id=tenant_id,
            role=user.role
        )
        
        return token
    
    def validate_jwt(self, token: str) -> TokenPayload:
        """
        Validate JWT token.
        
        Args:
            token: JWT token string
        
        Returns:
            TokenPayload with tenant_id, user_id, and role
        
        Raises:
            AuthenticationError: If token is invalid or expired
        """
        return self.jwt_handler.validate_jwt(token)
    
    async def validate_api_key(
        self,
        db: AsyncSession,
        tenant_id: str,
        api_key: str
    ) -> APIKeyPayload:
        """
        Validate API key.
        
        Args:
            db: Database session (must be set to tenant schema)
            tenant_id: Tenant identifier
            api_key: API key string
        
        Returns:
            APIKeyPayload with key_id, tenant_id, and role
        
        Raises:
            APIKeyError: If API key is invalid or revoked
        """
        return await self.api_key_manager.validate_api_key(db, tenant_id, api_key)
    
    def extract_tenant_context(
        self,
        payload: Union[TokenPayload, APIKeyPayload]
    ) -> dict:
        """
        Extract tenant context from authentication payload.
        
        Args:
            payload: TokenPayload or APIKeyPayload
        
        Returns:
            Dictionary with tenant_id, user_id/key_id, and role
        """
        if isinstance(payload, TokenPayload):
            return {
                "tenant_id": payload.tenant_id,
                "user_id": payload.user_id,
                "role": payload.role,
                "auth_type": "jwt"
            }
        elif isinstance(payload, APIKeyPayload):
            return {
                "tenant_id": payload.tenant_id,
                "key_id": str(payload.key_id),
                "role": payload.role,
                "auth_type": "api_key"
            }
        else:
            raise ValueError(f"Unknown payload type: {type(payload)}")


# Global auth service instance
auth_service = AuthService()
```

**Test File:** `tests/unit/test_auth_service.py`

```python
"""Unit tests for AuthService"""

import pytest
from app.auth.auth_service import AuthService, auth_service


class TestAuthService:
    def test_auth_service_initialization(self):
        """Test AuthService can be instantiated"""
        service = AuthService()
        assert service.jwt_handler is not None
        assert service.api_key_manager is not None
    
    def test_hash_password(self):
        """Test password hashing"""
        service = AuthService()
        password = "test_password_123"
        hashed = service.hash_password(password)
        
        assert hashed != password
        assert hashed.startswith("$2b$")
    
    def test_verify_password_correct(self):
        """Test password verification with correct password"""
        service = AuthService()
        password = "test_password_123"
        hashed = service.hash_password(password)
        
        assert service.verify_password(password, hashed) is True
    
    def test_verify_password_incorrect(self):
        """Test password verification with incorrect password"""
        service = AuthService()
        password = "test_password_123"
        wrong_password = "wrong_password_456"
        hashed = service.hash_password(password)
        
        assert service.verify_password(wrong_password, hashed) is False
    
    def test_extract_tenant_context_from_jwt_payload(self):
        """Test extracting context from JWT payload"""
        from app.auth.jwt_handler import TokenPayload
        
        service = AuthService()
        payload = TokenPayload(
            tenant_id="tenant_123",
            user_id="user_456",
            role="admin",
            exp=1234567890,
            iat=1234564290
        )
        
        context = service.extract_tenant_context(payload)
        
        assert context["tenant_id"] == "tenant_123"
        assert context["user_id"] == "user_456"
        assert context["role"] == "admin"
        assert context["auth_type"] == "jwt"
    
    def test_extract_tenant_context_from_api_key_payload(self):
        """Test extracting context from API key payload"""
        from uuid import uuid4
        from app.auth.api_key_manager import APIKeyPayload
        
        service = AuthService()
        key_id = uuid4()
        payload = APIKeyPayload(
            key_id=key_id,
            tenant_id="tenant_123",
            role="developer",
            name="Test Key"
        )
        
        context = service.extract_tenant_context(payload)
        
        assert context["tenant_id"] == "tenant_123"
        assert context["key_id"] == str(key_id)
        assert context["role"] == "developer"
        assert context["auth_type"] == "api_key"
```

---

### Tasks 4.1 & 4.2: Implement RBAC Engine

**File:** `app/auth/rbac.py`

```python
"""
RBAC (Role-Based Access Control) Engine

Provides permission checking and policy management for tenant-specific
authorization.
"""

from typing import Dict, List, Optional
import structlog

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.tenant import RBACPolicy


logger = structlog.get_logger(__name__)


# Default role definitions
DEFAULT_ROLES = {
    "admin": {
        "permissions": [
            {"action": "*", "resource": "*"}
        ]
    },
    "developer": {
        "permissions": [
            {"action": "read", "resource": "*"},
            {"action": "create", "resource": "resources"},
            {"action": "update", "resource": "resources"},
            {"action": "delete", "resource": "resources"},
            {"action": "create", "resource": "jobs"},
            {"action": "read", "resource": "jobs"}
        ]
    },
    "read_only": {
        "permissions": [
            {"action": "read", "resource": "*"}
        ]
    }
}


class RBACEngine:
    """
    RBAC policy engine for permission checking.
    
    Evaluates whether a user's role permits a specific action on a resource.
    Supports wildcard permissions and tenant-specific policy customization.
    """
    
    def __init__(self):
        logger.info("rbac_engine_initialized")
    
    def check_permission(
        self,
        role: str,
        action: str,
        resource: str,
        policy: Optional[Dict] = None
    ) -> bool:
        """
        Check if role has permission for action on resource.
        
        Args:
            role: User's role (e.g., admin, developer, read_only)
            action: Action to perform (e.g., create, read, update, delete)
            resource: Resource type (e.g., users, resources, jobs)
            policy: Optional custom policy dict (uses defaults if None)
        
        Returns:
            True if permission granted, False otherwise
        """
        # Use default policy if none provided
        if policy is None:
            policy = DEFAULT_ROLES.get(role, {})
        
        permissions = policy.get("permissions", [])
        
        # Check each permission
        for perm in permissions:
            perm_action = perm.get("action")
            perm_resource = perm.get("resource")
            
            # Check for wildcard or exact match
            action_match = perm_action == "*" or perm_action == action
            resource_match = perm_resource == "*" or perm_resource == resource
            
            if action_match and resource_match:
                logger.debug(
                    "permission_granted",
                    role=role,
                    action=action,
                    resource=resource
                )
                return True
        
        logger.warning(
            "permission_denied",
            role=role,
            action=action,
            resource=resource
        )
        return False
    
    async def get_tenant_policy(
        self,
        db: AsyncSession,
        role: str
    ) -> Optional[Dict]:
        """
        Get tenant-specific RBAC policy for role.
        
        Args:
            db: Database session (must be set to tenant schema)
            role: Role name
        
        Returns:
            Policy dict if found, None otherwise
        """
        stmt = select(RBACPolicy).where(RBACPolicy.role == role)
        result = await db.execute(stmt)
        policy_model = result.scalar_one_or_none()
        
        if policy_model is None:
            return None
        
        return {
            "permissions": policy_model.permissions
        }
    
    async def create_default_policies(
        self,
        db: AsyncSession,
        tenant_id: str
    ) -> None:
        """
        Create default RBAC policies for a new tenant.
        
        Args:
            db: Database session (must be set to tenant schema)
            tenant_id: Tenant identifier
        """
        for role, policy_data in DEFAULT_ROLES.items():
            policy = RBACPolicy(
                role=role,
                permissions=policy_data["permissions"]
            )
            db.add(policy)
        
        await db.commit()
        
        logger.info(
            "default_policies_created",
            tenant_id=tenant_id,
            roles=list(DEFAULT_ROLES.keys())
        )
    
    async def update_policy(
        self,
        db: AsyncSession,
        tenant_id: str,
        role: str,
        permissions: List[Dict]
    ) -> bool:
        """
        Update RBAC policy for a role.
        
        Args:
            db: Database session (must be set to tenant schema)
            tenant_id: Tenant identifier
            role: Role name
            permissions: List of permission dicts
        
        Returns:
            True if updated, False if role not found
        """
        stmt = select(RBACPolicy).where(RBACPolicy.role == role)
        result = await db.execute(stmt)
        policy = result.scalar_one_or_none()
        
        if policy is None:
            logger.warning("policy_not_found", tenant_id=tenant_id, role=role)
            return False
        
        policy.permissions = permissions
        await db.commit()
        
        logger.info(
            "policy_updated",
            tenant_id=tenant_id,
            role=role,
            permission_count=len(permissions)
        )
        return True


# Global RBAC engine instance
rbac_engine = RBACEngine()
```

**Test File:** `tests/unit/test_rbac.py`

```python
"""Unit tests for RBAC engine"""

import pytest
from app.auth.rbac import RBACEngine, DEFAULT_ROLES


class TestRBACEngine:
    def test_rbac_engine_initialization(self):
        """Test RBACEngine can be instantiated"""
        engine = RBACEngine()
        assert engine is not None
    
    def test_check_permission_admin_wildcard(self):
        """Test admin role has wildcard permissions"""
        engine = RBACEngine()
        
        # Admin should have all permissions
        assert engine.check_permission("admin", "create", "users") is True
        assert engine.check_permission("admin", "read", "resources") is True
        assert engine.check_permission("admin", "delete", "jobs") is True
    
    def test_check_permission_developer(self):
        """Test developer role permissions"""
        engine = RBACEngine()
        
        # Developer can read anything
        assert engine.check_permission("developer", "read", "users") is True
        assert engine.check_permission("developer", "read", "resources") is True
        
        # Developer can create/update/delete resources
        assert engine.check_permission("developer", "create", "resources") is True
        assert engine.check_permission("developer", "update", "resources") is True
        assert engine.check_permission("developer", "delete", "resources") is True
        
        # Developer cannot delete users
        assert engine.check_permission("developer", "delete", "users") is False
    
    def test_check_permission_read_only(self):
        """Test read_only role permissions"""
        engine = RBACEngine()
        
        # Read-only can read anything
        assert engine.check_permission("read_only", "read", "users") is True
        assert engine.check_permission("read_only", "read", "resources") is True
        
        # Read-only cannot create/update/delete
        assert engine.check_permission("read_only", "create", "resources") is False
        assert engine.check_permission("read_only", "update", "resources") is False
        assert engine.check_permission("read_only", "delete", "resources") is False
    
    def test_check_permission_unknown_role(self):
        """Test unknown role has no permissions"""
        engine = RBACEngine()
        
        assert engine.check_permission("unknown_role", "read", "users") is False
        assert engine.check_permission("unknown_role", "create", "resources") is False
    
    def test_check_permission_custom_policy(self):
        """Test permission checking with custom policy"""
        engine = RBACEngine()
        
        custom_policy = {
            "permissions": [
                {"action": "read", "resource": "resources"},
                {"action": "create", "resource": "resources"}
            ]
        }
        
        # Should have read and create on resources
        assert engine.check_permission("custom", "read", "resources", custom_policy) is True
        assert engine.check_permission("custom", "create", "resources", custom_policy) is True
        
        # Should not have delete on resources
        assert engine.check_permission("custom", "delete", "resources", custom_policy) is False
        
        # Should not have any permissions on users
        assert engine.check_permission("custom", "read", "users", custom_policy) is False
```

---

### Tasks 5.1-5.6: Implement Middleware

**File:** `app/middleware/auth_middleware.py`

```python
"""
Authentication Middleware

Extracts and validates JWT tokens or API keys from requests.
Sets tenant context in request state for downstream processing.
"""

from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
import structlog

from app.auth.auth_service import auth_service
from app.auth.jwt_handler import AuthenticationError
from app.auth.api_key_manager import APIKeyError


logger = structlog.get_logger(__name__)

security = HTTPBearer(auto_error=False)


async def auth_middleware(request: Request, call_next):
    """
    Authentication middleware.
    
    Extracts credentials from:
    1. Authorization header (Bearer token for JWT)
    2. X-API-Key header (for API keys)
    
    Sets request.state with:
    - tenant_id
    - user_id or key_id
    - role
    - auth_type
    """
    # Skip authentication for public endpoints
    public_paths = ["/", "/docs", "/redoc", "/openapi.json", "/health"]
    if request.url.path in public_paths:
        return await call_next(request)
    
    # Try JWT authentication first
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.replace("Bearer ", "")
        try:
            payload = auth_service.validate_jwt(token)
            context = auth_service.extract_tenant_context(payload)
            
            # Set request state
            request.state.tenant_id = context["tenant_id"]
            request.state.user_id = context["user_id"]
            request.state.role = context["role"]
            request.state.auth_type = "jwt"
            
            logger.info(
                "request_authenticated_jwt",
                tenant_id=context["tenant_id"],
                user_id=context["user_id"],
                path=request.url.path
            )
            
            return await call_next(request)
        except AuthenticationError as e:
            logger.warning("jwt_authentication_failed", error=e.code)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": {"code": e.code, "message": e.message}}
            )
    
    # Try API key authentication
    api_key = request.headers.get("X-API-Key")
    if api_key:
        # Extract tenant_id from path or query params
        # For now, require tenant_id in query params
        tenant_id = request.query_params.get("tenant_id")
        if not tenant_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": {"code": "MISSING_TENANT_ID", "message": "tenant_id required for API key authentication"}}
            )
        
        try:
            # Get tenant-specific database session
            from app.tenant_router import TenantRouter
            from app.database import db_manager
            
            tenant_router = TenantRouter(db_manager.engine)
            db = await tenant_router.get_session(tenant_id)
            
            payload = await auth_service.validate_api_key(db, tenant_id, api_key)
            context = auth_service.extract_tenant_context(payload)
            
            # Set request state
            request.state.tenant_id = context["tenant_id"]
            request.state.key_id = context["key_id"]
            request.state.role = context["role"]
            request.state.auth_type = "api_key"
            request.state.db = db
            
            logger.info(
                "request_authenticated_api_key",
                tenant_id=context["tenant_id"],
                key_id=context["key_id"],
                path=request.url.path
            )
            
            response = await call_next(request)
            await db.close()
            return response
            
        except APIKeyError as e:
            logger.warning("api_key_authentication_failed", error=e.code)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": {"code": e.code, "message": e.message}}
            )
    
    # No valid authentication provided
    logger.warning("no_authentication_provided", path=request.url.path)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": {"code": "MISSING_CREDENTIALS", "message": "Authentication required"}}
    )
```

**File:** `app/middleware/tenant_middleware.py`

```python
"""
Tenant Context Middleware

Sets up database session with tenant-specific schema routing.
"""

from fastapi import Request
import structlog

from app.tenant_router import TenantRouter
from app.database import db_manager


logger = structlog.get_logger(__name__)


async def tenant_middleware(request: Request, call_next):
    """
    Tenant context middleware.
    
    Creates database session with tenant schema routing based on
    tenant_id from authentication middleware.
    """
    # Skip for public endpoints
    public_paths = ["/", "/docs", "/redoc", "/openapi.json", "/health"]
    if request.url.path in public_paths:
        return await call_next(request)
    
    # Get tenant_id from request state (set by auth middleware)
    tenant_id = getattr(request.state, "tenant_id", None)
    
    if not tenant_id:
        logger.error("tenant_id_missing_in_request_state")
        return await call_next(request)
    
    # Create tenant-specific database session
    tenant_router = TenantRouter(db_manager.engine)
    db = await tenant_router.get_session(tenant_id)
    
    # Store in request state
    request.state.db = db
    
    logger.debug("tenant_context_established", tenant_id=tenant_id)
    
    try:
        response = await call_next(request)
        return response
    finally:
        await db.close()
```

**File:** `app/middleware/__init__.py`

```python
"""Middleware package"""

from app.middleware.auth_middleware import auth_middleware
from app.middleware.tenant_middleware import tenant_middleware

__all__ = [
    "auth_middleware",
    "tenant_middleware",
]
```

**Update `main.py` to add middleware:**

```python
# Add after CORS middleware
from app.middleware import auth_middleware, tenant_middleware

# Add middleware in correct order
app.middleware("http")(auth_middleware)
app.middleware("http")(tenant_middleware)
```

---

### Task 12.1: Implement Authentication Endpoints

**File:** `app/api/auth.py`

```python
"""
Authentication API Endpoints

Provides endpoints for user login, API key management, and authentication.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from typing import List
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.auth_service import auth_service
from app.database import get_db


router = APIRouter(prefix="/auth", tags=["Authentication"])


# Request/Response Models
class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    tenant_id: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 3600


class APIKeyCreateRequest(BaseModel):
    name: str
    role: str


class APIKeyResponse(BaseModel):
    id: UUID
    key: str | None = None  # Only returned on creation
    key_prefix: str
    name: str
    role: str
    created_at: str


@router.post("/login", response_model=LoginResponse)
async def login(
    request: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    User login endpoint.
    
    Authenticates user with email and password, returns JWT token.
    """
    token = await auth_service.login(
        db=db,
        tenant_id=request.tenant_id,
        email=request.email,
        password=request.password
    )
    
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": "INVALID_CREDENTIALS", "message": "Invalid email or password"}}
        )
    
    return LoginResponse(access_token=token)


@router.post("/api-keys", response_model=APIKeyResponse)
async def create_api_key(
    request: APIKeyCreateRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Create API key endpoint.
    
    Generates a new API key for the authenticated tenant.
    Requires admin role.
    """
    # TODO: Add role check (requires auth middleware)
    # For now, create key directly
    
    api_key, full_key = await auth_service.api_key_manager.create_api_key(
        db=db,
        tenant_id="tenant_example",  # TODO: Get from request.state
        role=request.role,
        name=request.name
    )
    
    return APIKeyResponse(
        id=api_key.id,
        key=full_key,  # Only returned once
        key_prefix=api_key.key_prefix,
        name=api_key.name,
        role=api_key.role,
        created_at=api_key.created_at.isoformat()
    )
```

---

## Remaining Implementation Summary

Due to space constraints, here's a quick reference for the remaining components:

### Core Services (Tasks 6.1, 7.1, 8.1-8.4, 9.1-9.2, 10.1)

1. **Rate Limiter** (`app/services/rate_limiter.py`): Redis-backed token bucket
2. **Metering Service** (`app/services/metering_service.py`): Usage tracking with TimescaleDB
3. **Celery Setup** (`app/celery_app.py`): Background job configuration
4. **Job Service** (`app/services/job_service.py`): Task management
5. **Autoscaling Engine** (`app/services/autoscaling_engine.py`): Scaling decisions
6. **Onboarding Service** (`app/services/onboarding_service.py`): Tenant provisioning

### API Endpoints (Tasks 12.2-12.7)

1. **Tenants** (`app/api/tenants.py`): Tenant management
2. **Resources** (`app/api/resources.py`): CRUD operations
3. **Jobs** (`app/api/jobs.py`): Background job status
4. **Usage** (`app/api/usage.py`): Metrics queries
5. **Health** (`app/api/health.py`): System health checks

### Error Handling (Tasks 13.1-13.3)

1. **Error Models** (`app/errors/models.py`): Pydantic error responses
2. **Exceptions** (`app/errors/exceptions.py`): Custom exception classes
3. **Handlers** (`app/errors/handlers.py`): FastAPI exception handlers

### Infrastructure (Tasks 17.1-17.4, 20.1-20.8, 21.1-21.6)

1. **Alembic**: Database migrations
2. **Terraform**: AWS infrastructure modules
3. **GitHub Actions**: CI/CD pipeline

---

## Testing Strategy

### Unit Tests
- Test each component in isolation
- Mock external dependencies
- Aim for 80%+ coverage

### Integration Tests
- Test API endpoints end-to-end
- Use test database with tenant schemas
- Test authentication flows

### Property-Based Tests (Optional)
- Use Hypothesis for edge case discovery
- Test tenant isolation properties
- Test RBAC permission combinations

---

## Deployment Guide

### Local Development

```bash
# Start services
docker-compose up -d postgres redis

# Run migrations
alembic upgrade head

# Start API
python main.py

# Start Celery worker
celery -A app.celery_app worker --loglevel=info
```

### Production Deployment

1. **Provision Infrastructure**: `terraform apply`
2. **Build Docker Images**: GitHub Actions
3. **Deploy to ECS**: Automated via CI/CD
4. **Run Migrations**: `alembic upgrade head`
5. **Monitor**: CloudWatch + Prometheus

---

## Next Steps

1. Complete Phase 1 tasks (Core MVP)
2. Test thoroughly with integration tests
3. Deploy to staging environment
4. Complete Phase 2 (Infrastructure)
5. Production deployment

---

**For detailed code examples and patterns, refer to the existing implementations in the codebase.**
