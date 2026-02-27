# Authentication Module

This module provides JWT-based authentication for the multi-tenant SaaS platform.

## Components

### JWTHandler

The `JWTHandler` class handles JWT token generation and validation using RS256 (RSA with SHA-256) signing algorithm.

**Features:**
- Secure token generation with RSA private key signing
- Token validation with signature verification
- Expiration time checking with configurable leeway for clock skew
- Structured token payload with tenant_id, user_id, and role

**Usage:**

```python
from app.auth import JWTHandler

# Initialize handler (uses keys from config)
jwt_handler = JWTHandler()

# Generate a token
token = jwt_handler.generate_jwt(
    user_id="user_123",
    tenant_id="tenant_abc",
    role="admin"
)

# Validate a token
try:
    payload = jwt_handler.validate_jwt(token)
    print(f"User: {payload.user_id}, Tenant: {payload.tenant_id}, Role: {payload.role}")
except AuthenticationError as e:
    print(f"Authentication failed: {e.code} - {e.message}")
```

### TokenPayload

Data class representing the JWT token payload with the following fields:
- `tenant_id`: Unique identifier for the tenant
- `user_id`: Unique identifier for the user
- `role`: User's role (e.g., admin, developer, read_only)
- `exp`: Expiration timestamp (Unix timestamp)
- `iat`: Issued at timestamp (Unix timestamp)

### AuthenticationError

Custom exception raised when JWT validation fails. Contains:
- `code`: Error code (e.g., TOKEN_EXPIRED, INVALID_TOKEN)
- `message`: Human-readable error message

## RSA Key Generation

RSA key pairs for JWT signing are generated using the provided script:

```bash
python scripts/generate_jwt_keys.py
```

This creates:
- `keys/jwt_private.pem`: Private key for signing tokens (keep secure!)
- `keys/jwt_public.pem`: Public key for verifying tokens

**Important:** Never commit private keys to version control. Add `keys/` to `.gitignore`.

## Configuration

JWT settings are configured in `app/config.py`:

```python
JWT_ALGORITHM: str = "RS256"
JWT_EXPIRATION_SECONDS: int = 3600  # 1 hour
JWT_PRIVATE_KEY_PATH: str = "keys/jwt_private.pem"
JWT_PUBLIC_KEY_PATH: str = "keys/jwt_public.pem"
```

## Security Considerations

1. **RS256 Algorithm**: Uses asymmetric encryption (RSA) for enhanced security
2. **Key Management**: Private keys must be kept secure and never exposed
3. **Token Expiration**: Tokens expire after 1 hour by default
4. **Clock Skew**: 10-second leeway for clock synchronization issues
5. **Signature Verification**: All tokens are verified against the public key

## Testing

Unit tests are provided in `tests/unit/test_jwt_handler.py`:

```bash
pytest tests/unit/test_jwt_handler.py -v
```

Tests cover:
- Token generation with various roles
- Token validation (valid, expired, invalid signature)
- Round-trip token generation and validation
- Error handling for malformed tokens
- Missing required fields validation
