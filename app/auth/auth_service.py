"""
Authentication Service

Unified authentication service that integrates JWT token handling and API key
management. Provides a single interface for credential verification, tenant
context extraction, and authentication operations.

Requirements: 2.1, 2.3, 2.6, 4.1
"""

from typing import Optional, Union
from uuid import UUID
import structlog

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.auth.jwt_handler import JWTHandler, TokenPayload, AuthenticationError
from app.auth.api_key_manager import APIKeyManager, APIKeyPayload, APIKeyError
from app.models.tenant import User
from app.config import settings


logger = structlog.get_logger(__name__)


class TenantContext:
    """
    Tenant context extracted from authentication credentials.
    
    Contains all information needed to identify and authorize a request
    within a tenant's scope.
    """
    
    def __init__(
        self,
        tenant_id: str,
        user_id: str,
        role: str,
        auth_method: str,
        api_key_id: Optional[UUID] = None
    ):
        self.tenant_id = tenant_id
        self.user_id = user_id
        self.role = role
        self.auth_method = auth_method  # "jwt" or "api_key"
        self.api_key_id = api_key_id
    
    def to_dict(self) -> dict:
        """Convert context to dictionary"""
        return {
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "role": self.role,
            "auth_method": self.auth_method,
            "api_key_id": str(self.api_key_id) if self.api_key_id else None
        }
    
    def __repr__(self) -> str:
        return f"<TenantContext(tenant_id={self.tenant_id}, user_id={self.user_id}, role={self.role}, method={self.auth_method})>"


class AuthService:
    """
    Unified authentication service.
    
    Provides a single interface for:
    - JWT token generation and validation
    - API key creation and validation
    - Credential verification
    - Tenant context extraction
    
    This service integrates JWTHandler and APIKeyManager to provide
    a consistent authentication interface for the application.
    
    Requirements:
    - 2.1: Generate JWT tokens with tenant and user information
    - 2.3: Extract tenant context from validated JWT tokens
    - 2.6: Include tenant identifier, user identifier, and role in JWT payload
    - 4.1: Generate and validate API keys for tenant authentication
    """
    
    def __init__(
        self,
        jwt_handler: Optional[JWTHandler] = None,
        api_key_manager: Optional[APIKeyManager] = None
    ):
        """
        Initialize authentication service.
        
        Args:
            jwt_handler: JWT handler instance (creates default if not provided)
            api_key_manager: API key manager instance (creates default if not provided)
        """
        self.jwt_handler = jwt_handler or JWTHandler()
        self.api_key_manager = api_key_manager or APIKeyManager()
        
        logger.info("AuthService initialized")
    
    def generate_jwt(self, user_id: str, tenant_id: str, role: str) -> str:
        """
        Generate a signed JWT token.
        
        Creates a JWT token containing tenant_id, user_id, and role information.
        The token is signed using RS256 algorithm and expires after the configured
        duration (default: 1 hour).
        
        Args:
            user_id: Unique identifier for the user
            tenant_id: Unique identifier for the tenant
            role: User's role (e.g., admin, developer, read_only)
        
        Returns:
            Signed JWT token string
        
        Raises:
            Exception: If token generation fails
        
        Requirements: 2.1, 2.6
        
        Example:
            token = auth_service.generate_jwt(
                user_id="user_123",
                tenant_id="tenant_abc",
                role="admin"
            )
        """
        return self.jwt_handler.generate_jwt(user_id, tenant_id, role)
    
    def validate_jwt(self, token: str) -> TokenPayload:
        """
        Validate JWT token and extract payload.
        
        Verifies the token signature and expiration, then returns the payload
        containing tenant_id, user_id, and role information.
        
        Args:
            token: JWT token string to validate
        
        Returns:
            TokenPayload object containing token claims
        
        Raises:
            AuthenticationError: If token is invalid, expired, or malformed
        
        Requirements: 2.3
        
        Example:
            try:
                payload = auth_service.validate_jwt(token)
                print(f"Tenant: {payload.tenant_id}, User: {payload.user_id}")
            except AuthenticationError as e:
                print(f"Authentication failed: {e.message}")
        """
        return self.jwt_handler.validate_jwt(token)
    
    async def create_api_key(
        self,
        db: AsyncSession,
        tenant_id: str,
        role: str,
        name: str,
        created_by: Optional[UUID] = None
    ) -> tuple[UUID, str]:
        """
        Create a new API key for a tenant.
        
        Generates a secure random API key, hashes the secret, and stores it
        in the tenant's database schema. The full key is only returned once
        at creation time.
        
        Args:
            db: Database session (must be set to tenant schema)
            tenant_id: Tenant identifier
            role: Role associated with the API key
            name: Human-readable name for the API key
            created_by: Optional user ID who created the key
        
        Returns:
            Tuple of (key_id, full_key_string)
        
        Raises:
            Exception: If database operation fails
        
        Requirements: 4.1
        
        Example:
            key_id, full_key = await auth_service.create_api_key(
                db=session,
                tenant_id="tenant_abc",
                role="developer",
                name="Production API Key"
            )
            # Store full_key securely - it cannot be retrieved later
        """
        api_key, full_key = await self.api_key_manager.create_api_key(
            db=db,
            tenant_id=tenant_id,
            role=role,
            name=name,
            created_by=created_by
        )
        
        return api_key.id, full_key
    
    async def validate_api_key(
        self,
        db: AsyncSession,
        tenant_id: str,
        key: str
    ) -> APIKeyPayload:
        """
        Validate an API key and return its payload.
        
        Verifies the API key format, checks it exists and is not revoked,
        and validates the secret hash. Updates the last_used_at timestamp
        on successful validation.
        
        Args:
            db: Database session (must be set to tenant schema)
            tenant_id: Tenant identifier
            key: Full API key string (prefix_secret)
        
        Returns:
            APIKeyPayload containing key_id, tenant_id, role, and name
        
        Raises:
            APIKeyError: If key is invalid, revoked, or verification fails
        
        Requirements: 4.1
        
        Example:
            try:
                payload = await auth_service.validate_api_key(
                    db=session,
                    tenant_id="tenant_abc",
                    key="abc12345_secretkey..."
                )
                print(f"API Key: {payload.name}, Role: {payload.role}")
            except APIKeyError as e:
                print(f"API key validation failed: {e.message}")
        """
        return await self.api_key_manager.validate_api_key(
            db=db,
            tenant_id=tenant_id,
            key=key
        )
    
    async def revoke_api_key(
        self,
        db: AsyncSession,
        tenant_id: str,
        key_id: UUID
    ) -> bool:
        """
        Revoke an API key.
        
        Marks the API key as revoked by setting the revoked_at timestamp.
        Revoked keys cannot be used for authentication.
        
        Args:
            db: Database session (must be set to tenant schema)
            tenant_id: Tenant identifier
            key_id: UUID of the API key to revoke
        
        Returns:
            True if key was revoked, False if key not found
        
        Raises:
            Exception: If database operation fails
        
        Requirements: 4.1
        
        Example:
            success = await auth_service.revoke_api_key(
                db=session,
                tenant_id="tenant_abc",
                key_id=UUID("...")
            )
        """
        return await self.api_key_manager.revoke_api_key(
            db=db,
            tenant_id=tenant_id,
            key_id=key_id
        )
    
    def extract_tenant_context_from_jwt(self, token: str) -> TenantContext:
        """
        Extract tenant context from JWT token.
        
        Validates the JWT token and extracts tenant_id, user_id, and role
        information into a TenantContext object.
        
        Args:
            token: JWT token string
        
        Returns:
            TenantContext object with tenant information
        
        Raises:
            AuthenticationError: If token validation fails
        
        Requirements: 2.3, 2.6
        
        Example:
            context = auth_service.extract_tenant_context_from_jwt(token)
            print(f"Tenant: {context.tenant_id}, Role: {context.role}")
        """
        payload = self.validate_jwt(token)
        
        return TenantContext(
            tenant_id=payload.tenant_id,
            user_id=payload.user_id,
            role=payload.role,
            auth_method="jwt"
        )
    
    async def extract_tenant_context_from_api_key(
        self,
        db: AsyncSession,
        tenant_id: str,
        key: str
    ) -> TenantContext:
        """
        Extract tenant context from API key.
        
        Validates the API key and extracts tenant_id, role, and key_id
        information into a TenantContext object. Note that API keys don't
        have a specific user_id, so the user_id will be set to "api_key".
        
        Args:
            db: Database session (must be set to tenant schema)
            tenant_id: Tenant identifier
            key: Full API key string
        
        Returns:
            TenantContext object with tenant information
        
        Raises:
            APIKeyError: If API key validation fails
        
        Requirements: 4.1
        
        Example:
            context = await auth_service.extract_tenant_context_from_api_key(
                db=session,
                tenant_id="tenant_abc",
                key="abc12345_secretkey..."
            )
            print(f"API Key: {context.api_key_id}, Role: {context.role}")
        """
        payload = await self.validate_api_key(db, tenant_id, key)
        
        return TenantContext(
            tenant_id=payload.tenant_id,
            user_id="api_key",  # API keys don't have a specific user_id
            role=payload.role,
            auth_method="api_key",
            api_key_id=payload.key_id
        )
    
    async def verify_user_credentials(
        self,
        db: AsyncSession,
        email: str,
        password: str
    ) -> Optional[User]:
        """
        Verify user credentials (email and password).
        
        Queries the user from the database and verifies the password hash.
        This method should be called within a tenant context (database session
        must be set to tenant schema).
        
        Args:
            db: Database session (must be set to tenant schema)
            email: User email address
            password: Plain text password to verify
        
        Returns:
            User object if credentials are valid, None otherwise
        
        Requirements: 2.1
        
        Example:
            user = await auth_service.verify_user_credentials(
                db=session,
                email="user@example.com",
                password="password123"
            )
            if user:
                token = auth_service.generate_jwt(
                    user_id=str(user.id),
                    tenant_id=tenant_id,
                    role=user.role
                )
        """
        try:
            # Import bcrypt here to avoid circular imports
            import bcrypt
            
            # Query user by email
            stmt = select(User).where(User.email == email)
            result = await db.execute(stmt)
            user = result.scalar_one_or_none()
            
            if user is None:
                logger.warning("User not found", email=email)
                return None
            
            # Verify password hash
            password_valid = bcrypt.checkpw(
                password.encode('utf-8'),
                user.password_hash.encode('utf-8')
            )
            
            if not password_valid:
                logger.warning("Invalid password", email=email, user_id=str(user.id))
                return None
            
            logger.info(
                "User credentials verified",
                email=email,
                user_id=str(user.id),
                role=user.role
            )
            
            return user
            
        except Exception as e:
            logger.error(
                "Error verifying user credentials",
                email=email,
                error=str(e)
            )
            return None
    
    def extract_tenant_context(
        self,
        token: Optional[str] = None,
        api_key: Optional[str] = None,
        db: Optional[AsyncSession] = None,
        tenant_id: Optional[str] = None
    ) -> Union[TenantContext, None]:
        """
        Extract tenant context from either JWT token or API key.
        
        This is a convenience method that determines the authentication method
        and extracts the appropriate tenant context. For API key authentication,
        this method is synchronous wrapper - use extract_tenant_context_from_api_key
        directly for async API key validation.
        
        Args:
            token: Optional JWT token string
            api_key: Optional API key string
            db: Optional database session (required for API key validation)
            tenant_id: Optional tenant ID (required for API key validation)
        
        Returns:
            TenantContext object if authentication succeeds, None otherwise
        
        Note:
            This method only supports synchronous JWT validation.
            For API key validation, use extract_tenant_context_from_api_key directly.
        
        Requirements: 2.3, 4.1
        
        Example:
            # JWT authentication
            context = auth_service.extract_tenant_context(token=jwt_token)
            
            # API key authentication (use async method instead)
            context = await auth_service.extract_tenant_context_from_api_key(
                db=session,
                tenant_id="tenant_abc",
                key=api_key
            )
        """
        if token:
            try:
                return self.extract_tenant_context_from_jwt(token)
            except AuthenticationError as e:
                logger.warning("JWT authentication failed", error=e.message)
                return None
        
        # For API key authentication, caller should use async method directly
        logger.warning("extract_tenant_context called without token - use async methods for API key auth")
        return None
