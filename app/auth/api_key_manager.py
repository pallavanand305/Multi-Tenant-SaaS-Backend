"""
API Key Manager

Handles API key generation, validation, and revocation for tenant authentication.
API keys provide an alternative to JWT tokens for machine-to-machine authentication.
Keys are securely generated, hashed with bcrypt, and can be revoked independently.

Requirements: 4.1, 4.2, 4.3, 4.4
"""

import secrets
import bcrypt
from datetime import datetime
from typing import Optional
from uuid import UUID
import structlog

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.tenant import APIKey


logger = structlog.get_logger(__name__)


class APIKeyPayload:
    """API key validation payload structure"""
    
    def __init__(self, key_id: UUID, tenant_id: str, role: str, name: str):
        self.key_id = key_id
        self.tenant_id = tenant_id
        self.role = role
        self.name = name
    
    def to_dict(self) -> dict:
        """Convert payload to dictionary"""
        return {
            "key_id": str(self.key_id),
            "tenant_id": self.tenant_id,
            "role": self.role,
            "name": self.name
        }


class APIKeyError(Exception):
    """API key error with error code"""
    
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


class APIKeyManager:
    """
    API key manager for tenant authentication.
    
    Provides methods for:
    - Generating secure API keys with bcrypt hashing
    - Validating API keys with hash verification
    - Revoking API keys independently
    - Tracking API key usage
    
    API keys are formatted as: {prefix}_{secret}
    - prefix: 8 random characters for identification (stored in plaintext)
    - secret: 32 random characters (hashed with bcrypt)
    
    Requirements: 4.1, 4.2, 4.3, 4.4
    """
    
    def __init__(self, bcrypt_rounds: int = 12):
        """
        Initialize API key manager.
        
        Args:
            bcrypt_rounds: Number of bcrypt rounds for hashing (default: 12)
        """
        self.bcrypt_rounds = bcrypt_rounds
        logger.info("api_key_manager_initialized", bcrypt_rounds=bcrypt_rounds)
    
    def _generate_key_string(self) -> tuple[str, str, str]:
        """
        Generate a secure random API key string.
        
        Returns:
            Tuple of (full_key, prefix, secret)
            - full_key: Complete API key string (prefix_secret)
            - prefix: First 8 characters for identification
            - secret: 32 character secret portion
        """
        # Generate cryptographically secure random strings
        prefix = secrets.token_urlsafe(6)[:8]  # 8 characters for prefix
        secret = secrets.token_urlsafe(24)[:32]  # 32 characters for secret
        
        full_key = f"{prefix}_{secret}"
        
        return full_key, prefix, secret
    
    def _hash_secret(self, secret: str) -> str:
        """
        Hash API key secret using bcrypt.
        
        Args:
            secret: The secret portion of the API key
        
        Returns:
            Bcrypt hashed secret
        """
        salt = bcrypt.gensalt(rounds=self.bcrypt_rounds)
        hashed = bcrypt.hashpw(secret.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def _verify_secret(self, secret: str, hashed_secret: str) -> bool:
        """
        Verify API key secret against hashed value.
        
        Args:
            secret: The secret to verify
            hashed_secret: The bcrypt hashed secret from database
        
        Returns:
            True if secret matches, False otherwise
        """
        try:
            return bcrypt.checkpw(
                secret.encode('utf-8'),
                hashed_secret.encode('utf-8')
            )
        except Exception as e:
            logger.error("secret_verification_error", error=str(e))
            return False
    
    async def create_api_key(
        self,
        db: AsyncSession,
        tenant_id: str,
        role: str,
        name: str,
        created_by: Optional[UUID] = None
    ) -> tuple[APIKey, str]:
        """
        Create a new API key for a tenant.
        
        Generates a secure random API key, hashes the secret with bcrypt,
        and stores it in the tenant's database schema. The full key is only
        returned once at creation time and cannot be retrieved later.
        
        Args:
            db: Database session (must be set to tenant schema)
            tenant_id: Tenant identifier
            role: Role associated with the API key (admin, developer, read_only)
            name: Human-readable name for the API key
            created_by: Optional user ID who created the key
        
        Returns:
            Tuple of (APIKey model, full_key_string)
            The full key string should be returned to the user and stored securely
        
        Raises:
            Exception: If database operation fails
        
        Requirements: 4.1, 4.2
        """
        try:
            # Generate secure API key
            full_key, prefix, secret = self._generate_key_string()
            
            # Hash the secret
            hashed_secret = self._hash_secret(secret)
            
            # Create API key record
            api_key = APIKey(
                key_prefix=prefix,
                hashed_secret=hashed_secret,
                name=name,
                role=role,
                created_by=created_by
            )
            
            db.add(api_key)
            await db.commit()
            await db.refresh(api_key)
            
            logger.info(
                "api_key_created",
                key_id=str(api_key.id),
                tenant_id=tenant_id,
                role=role,
                name=name,
                prefix=prefix,
                created_by=str(created_by) if created_by else None
            )
            
            return api_key, full_key
            
        except Exception as e:
            await db.rollback()
            logger.error(
                "api_key_creation_failed",
                tenant_id=tenant_id,
                role=role,
                name=name,
                error=str(e)
            )
            raise
    
    async def validate_api_key(
        self,
        db: AsyncSession,
        tenant_id: str,
        key: str
    ) -> APIKeyPayload:
        """
        Validate an API key and return its payload.
        
        Performs the following checks:
        - Key format validation (prefix_secret)
        - Key existence in database
        - Key not revoked
        - Secret hash verification
        
        Updates last_used_at timestamp on successful validation.
        
        Args:
            db: Database session (must be set to tenant schema)
            tenant_id: Tenant identifier
            key: Full API key string (prefix_secret)
        
        Returns:
            APIKeyPayload containing key_id, tenant_id, role, and name
        
        Raises:
            APIKeyError: If key is invalid, revoked, or verification fails
        
        Requirements: 4.2, 4.3
        """
        try:
            # Parse key format
            if '_' not in key:
                logger.warning("api_key_invalid_format", tenant_id=tenant_id)
                raise APIKeyError(
                    "INVALID_API_KEY",
                    "API key format is invalid"
                )
            
            prefix, secret = key.split('_', 1)
            
            # Query API key by prefix
            stmt = select(APIKey).where(
                APIKey.key_prefix == prefix,
                APIKey.revoked_at.is_(None)
            )
            result = await db.execute(stmt)
            api_key = result.scalar_one_or_none()
            
            if api_key is None:
                logger.warning(
                    "api_key_not_found",
                    tenant_id=tenant_id,
                    prefix=prefix
                )
                raise APIKeyError(
                    "INVALID_API_KEY",
                    "API key not found or has been revoked"
                )
            
            # Verify secret hash
            if not self._verify_secret(secret, api_key.hashed_secret):
                logger.warning(
                    "api_key_invalid_secret",
                    tenant_id=tenant_id,
                    key_id=str(api_key.id),
                    prefix=prefix
                )
                raise APIKeyError(
                    "INVALID_API_KEY",
                    "API key secret verification failed"
                )
            
            # Update last used timestamp
            api_key.last_used_at = datetime.utcnow()
            await db.commit()
            
            logger.info(
                "api_key_validated",
                key_id=str(api_key.id),
                tenant_id=tenant_id,
                role=api_key.role,
                name=api_key.name
            )
            
            # Return payload
            return APIKeyPayload(
                key_id=api_key.id,
                tenant_id=tenant_id,
                role=api_key.role,
                name=api_key.name
            )
            
        except APIKeyError:
            raise
        except Exception as e:
            logger.error(
                "api_key_validation_error",
                tenant_id=tenant_id,
                error=str(e)
            )
            raise APIKeyError(
                "VALIDATION_ERROR",
                f"API key validation failed: {str(e)}"
            )
    
    async def revoke_api_key(
        self,
        db: AsyncSession,
        tenant_id: str,
        key_id: UUID
    ) -> bool:
        """
        Revoke an API key.
        
        Sets the revoked_at timestamp to mark the key as inactive.
        Revoked keys cannot be used for authentication and will fail
        validation checks.
        
        Args:
            db: Database session (must be set to tenant schema)
            tenant_id: Tenant identifier
            key_id: UUID of the API key to revoke
        
        Returns:
            True if key was revoked, False if key not found
        
        Raises:
            Exception: If database operation fails
        
        Requirements: 4.4
        """
        try:
            # Update API key to set revoked_at
            stmt = (
                update(APIKey)
                .where(
                    APIKey.id == key_id,
                    APIKey.revoked_at.is_(None)
                )
                .values(revoked_at=datetime.utcnow())
            )
            
            result = await db.execute(stmt)
            await db.commit()
            
            if result.rowcount == 0:
                logger.warning(
                    "api_key_not_found_for_revocation",
                    tenant_id=tenant_id,
                    key_id=str(key_id)
                )
                return False
            
            logger.info(
                "api_key_revoked",
                key_id=str(key_id),
                tenant_id=tenant_id
            )
            
            return True
            
        except Exception as e:
            await db.rollback()
            logger.error(
                "api_key_revocation_failed",
                tenant_id=tenant_id,
                key_id=str(key_id),
                error=str(e)
            )
            raise
