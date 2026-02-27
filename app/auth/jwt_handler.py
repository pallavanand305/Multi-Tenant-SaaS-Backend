"""
JWT Token Handler

Handles JWT token generation and validation using RS256 (RSA with SHA-256) signing.
Tokens contain tenant_id, user_id, and role information for authentication and authorization.
"""

import jwt
from datetime import datetime, timedelta
from typing import Dict, Optional
from pathlib import Path
import structlog

from app.config import settings


logger = structlog.get_logger(__name__)


class TokenPayload:
    """JWT token payload structure"""
    
    def __init__(self, tenant_id: str, user_id: str, role: str, exp: int, iat: int):
        self.tenant_id = tenant_id
        self.user_id = user_id
        self.role = role
        self.exp = exp
        self.iat = iat
    
    def to_dict(self) -> Dict:
        """Convert payload to dictionary"""
        return {
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "role": self.role,
            "exp": self.exp,
            "iat": self.iat
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "TokenPayload":
        """Create payload from dictionary"""
        return cls(
            tenant_id=data["tenant_id"],
            user_id=data["user_id"],
            role=data["role"],
            exp=data["exp"],
            iat=data["iat"]
        )


class AuthenticationError(Exception):
    """Authentication error with error code"""
    
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


class JWTHandler:
    """
    JWT token handler using RS256 signing algorithm.
    
    Provides methods for:
    - Generating signed JWT tokens with tenant and user information
    - Validating JWT tokens including signature and expiration checks
    - Loading RSA key pairs for signing and verification
    """
    
    def __init__(
        self,
        private_key_path: Optional[str] = None,
        public_key_path: Optional[str] = None,
        algorithm: str = "RS256",
        expiration_seconds: int = 3600
    ):
        """
        Initialize JWT handler with RSA keys.
        
        Args:
            private_key_path: Path to RSA private key file (PEM format)
            public_key_path: Path to RSA public key file (PEM format)
            algorithm: JWT signing algorithm (default: RS256)
            expiration_seconds: Token expiration time in seconds (default: 3600)
        """
        self.algorithm = algorithm
        self.expiration_seconds = expiration_seconds
        
        # Use settings if paths not provided
        private_key_path = private_key_path or settings.JWT_PRIVATE_KEY_PATH
        public_key_path = public_key_path or settings.JWT_PUBLIC_KEY_PATH
        
        # Load RSA keys
        self.private_key = self._load_private_key(private_key_path)
        self.public_key = self._load_public_key(public_key_path)
        
        logger.info(
            "jwt_handler_initialized",
            algorithm=self.algorithm,
            expiration_seconds=self.expiration_seconds
        )
    
    def _load_private_key(self, key_path: str) -> str:
        """Load RSA private key from file"""
        try:
            path = Path(key_path)
            if not path.exists():
                raise FileNotFoundError(f"Private key not found at {key_path}")
            
            with open(path, "r") as f:
                private_key = f.read()
            
            logger.info("private_key_loaded", path=key_path)
            return private_key
        except Exception as e:
            logger.error("failed_to_load_private_key", path=key_path, error=str(e))
            raise
    
    def _load_public_key(self, key_path: str) -> str:
        """Load RSA public key from file"""
        try:
            path = Path(key_path)
            if not path.exists():
                raise FileNotFoundError(f"Public key not found at {key_path}")
            
            with open(path, "r") as f:
                public_key = f.read()
            
            logger.info("public_key_loaded", path=key_path)
            return public_key
        except Exception as e:
            logger.error("failed_to_load_public_key", path=key_path, error=str(e))
            raise
    
    def generate_jwt(self, user_id: str, tenant_id: str, role: str) -> str:
        """
        Generate a signed JWT token.
        
        Args:
            user_id: Unique identifier for the user
            tenant_id: Unique identifier for the tenant
            role: User's role (e.g., admin, developer, read_only)
        
        Returns:
            Signed JWT token string
        
        Raises:
            Exception: If token generation fails
        """
        try:
            now = datetime.utcnow()
            expiration = now + timedelta(seconds=self.expiration_seconds)
            
            payload = {
                "tenant_id": tenant_id,
                "user_id": user_id,
                "role": role,
                "iat": int(now.timestamp()),
                "exp": int(expiration.timestamp())
            }
            
            token = jwt.encode(
                payload,
                self.private_key,
                algorithm=self.algorithm
            )
            
            logger.info(
                "jwt_generated",
                user_id=user_id,
                tenant_id=tenant_id,
                role=role,
                expires_at=expiration.isoformat()
            )
            
            return token
        except Exception as e:
            logger.error(
                "jwt_generation_failed",
                user_id=user_id,
                tenant_id=tenant_id,
                error=str(e)
            )
            raise
    
    def validate_jwt(self, token: str) -> TokenPayload:
        """
        Validate JWT token and extract payload.
        
        Performs the following checks:
        - Signature verification using RSA public key
        - Expiration time validation
        - Required fields presence
        
        Args:
            token: JWT token string to validate
        
        Returns:
            TokenPayload object containing token claims
        
        Raises:
            AuthenticationError: If token is invalid, expired, or malformed
        """
        try:
            # Decode and verify token with leeway for clock skew
            payload = jwt.decode(
                token,
                self.public_key,
                algorithms=[self.algorithm],
                leeway=10  # 10 seconds leeway for clock skew
            )
            
            # Validate required fields
            required_fields = ["tenant_id", "user_id", "role", "exp", "iat"]
            missing_fields = [field for field in required_fields if field not in payload]
            
            if missing_fields:
                logger.warning(
                    "jwt_missing_fields",
                    missing_fields=missing_fields
                )
                raise AuthenticationError(
                    "INVALID_TOKEN",
                    f"Token missing required fields: {', '.join(missing_fields)}"
                )
            
            # Create token payload object
            token_payload = TokenPayload.from_dict(payload)
            
            logger.info(
                "jwt_validated",
                user_id=token_payload.user_id,
                tenant_id=token_payload.tenant_id,
                role=token_payload.role
            )
            
            return token_payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("jwt_expired", token_prefix=token[:20] if len(token) > 20 else token)
            raise AuthenticationError(
                "TOKEN_EXPIRED",
                "JWT token has expired"
            )
        except jwt.InvalidSignatureError:
            logger.warning("jwt_invalid_signature", token_prefix=token[:20] if len(token) > 20 else token)
            raise AuthenticationError(
                "INVALID_TOKEN",
                "JWT signature verification failed"
            )
        except jwt.DecodeError:
            logger.warning("jwt_decode_error", token_prefix=token[:20] if len(token) > 20 else token)
            raise AuthenticationError(
                "INVALID_TOKEN",
                "JWT token is malformed"
            )
        except jwt.InvalidTokenError as e:
            logger.warning("jwt_invalid", error=str(e), token_prefix=token[:20] if len(token) > 20 else token)
            raise AuthenticationError(
                "INVALID_TOKEN",
                f"JWT token is invalid: {str(e)}"
            )
        except Exception as e:
            logger.error("jwt_validation_error", error=str(e))
            raise AuthenticationError(
                "INVALID_TOKEN",
                f"Token validation failed: {str(e)}"
            )
