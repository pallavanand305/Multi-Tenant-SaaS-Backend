"""
Unit Tests for JWT Handler

Tests JWT token generation and validation functionality.
"""

import pytest
import jwt
from datetime import datetime, timedelta
from pathlib import Path

from app.auth.jwt_handler import JWTHandler, TokenPayload, AuthenticationError


@pytest.fixture
def jwt_handler():
    """Create JWT handler instance for testing"""
    return JWTHandler(
        private_key_path="keys/jwt_private.pem",
        public_key_path="keys/jwt_public.pem",
        algorithm="RS256",
        expiration_seconds=3600
    )


@pytest.fixture
def sample_token_data():
    """Sample token data for testing"""
    return {
        "user_id": "user_123",
        "tenant_id": "tenant_abc",
        "role": "admin"
    }


class TestJWTGeneration:
    """Test JWT token generation"""
    
    def test_generate_jwt_returns_valid_token(self, jwt_handler, sample_token_data):
        """Test that generate_jwt returns a non-empty token string"""
        token = jwt_handler.generate_jwt(
            user_id=sample_token_data["user_id"],
            tenant_id=sample_token_data["tenant_id"],
            role=sample_token_data["role"]
        )
        
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0
        # JWT tokens have 3 parts separated by dots
        assert token.count(".") == 2
    
    def test_generate_jwt_includes_required_claims(self, jwt_handler, sample_token_data):
        """Test that generated token includes all required claims"""
        token = jwt_handler.generate_jwt(
            user_id=sample_token_data["user_id"],
            tenant_id=sample_token_data["tenant_id"],
            role=sample_token_data["role"]
        )
        
        # Decode without verification to check claims
        payload = jwt.decode(token, options={"verify_signature": False})
        
        assert "user_id" in payload
        assert "tenant_id" in payload
        assert "role" in payload
        assert "iat" in payload
        assert "exp" in payload
        
        assert payload["user_id"] == sample_token_data["user_id"]
        assert payload["tenant_id"] == sample_token_data["tenant_id"]
        assert payload["role"] == sample_token_data["role"]
    
    def test_generate_jwt_sets_correct_expiration(self, jwt_handler, sample_token_data):
        """Test that token expiration is set correctly"""
        before_generation = datetime.utcnow()
        
        token = jwt_handler.generate_jwt(
            user_id=sample_token_data["user_id"],
            tenant_id=sample_token_data["tenant_id"],
            role=sample_token_data["role"]
        )
        
        after_generation = datetime.utcnow()
        
        payload = jwt.decode(token, options={"verify_signature": False})
        
        exp_timestamp = payload["exp"]
        iat_timestamp = payload["iat"]
        
        # Check that expiration is approximately 3600 seconds after issued time
        assert exp_timestamp - iat_timestamp == 3600
        
        # Check that issued time is within the generation window (with 1 second tolerance)
        assert int(before_generation.timestamp()) <= iat_timestamp <= int(after_generation.timestamp()) + 1
    
    def test_generate_jwt_with_different_roles(self, jwt_handler, sample_token_data):
        """Test token generation with different role values"""
        roles = ["admin", "developer", "read_only"]
        
        for role in roles:
            token = jwt_handler.generate_jwt(
                user_id=sample_token_data["user_id"],
                tenant_id=sample_token_data["tenant_id"],
                role=role
            )
            
            payload = jwt.decode(token, options={"verify_signature": False})
            assert payload["role"] == role


class TestJWTValidation:
    """Test JWT token validation"""
    
    def test_validate_jwt_accepts_valid_token(self, jwt_handler, sample_token_data):
        """Test that validate_jwt accepts a valid token"""
        # Create a token with a far future expiration to avoid clock issues
        now = datetime.utcnow()
        payload = {
            "user_id": sample_token_data["user_id"],
            "tenant_id": sample_token_data["tenant_id"],
            "role": sample_token_data["role"],
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(days=365)).timestamp())  # 1 year expiration
        }
        
        token = jwt.encode(
            payload,
            jwt_handler.private_key,
            algorithm="RS256"
        )
        
        validated_payload = jwt_handler.validate_jwt(token)
        
        assert isinstance(validated_payload, TokenPayload)
        assert validated_payload.user_id == sample_token_data["user_id"]
        assert validated_payload.tenant_id == sample_token_data["tenant_id"]
        assert validated_payload.role == sample_token_data["role"]
        assert validated_payload.exp > 0
        assert validated_payload.iat > 0
    
    def test_validate_jwt_rejects_expired_token(self, jwt_handler, sample_token_data):
        """Test that validate_jwt rejects expired tokens"""
        # Create a token that expired 1 hour ago
        now = datetime.utcnow()
        expired_time = now - timedelta(hours=2)
        
        payload = {
            "user_id": sample_token_data["user_id"],
            "tenant_id": sample_token_data["tenant_id"],
            "role": sample_token_data["role"],
            "iat": int(expired_time.timestamp()),
            "exp": int((expired_time + timedelta(hours=1)).timestamp())
        }
        
        expired_token = jwt.encode(
            payload,
            jwt_handler.private_key,
            algorithm="RS256"
        )
        
        with pytest.raises(AuthenticationError) as exc_info:
            jwt_handler.validate_jwt(expired_token)
        
        assert exc_info.value.code == "TOKEN_EXPIRED"
        assert "expired" in exc_info.value.message.lower()
    
    def test_validate_jwt_rejects_invalid_signature(self, jwt_handler, sample_token_data):
        """Test that validate_jwt rejects tokens with invalid signatures"""
        # Generate a token with a different key
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        
        # Generate a different private key
        wrong_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        wrong_private_pem = wrong_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        now = datetime.utcnow()
        payload = {
            "user_id": sample_token_data["user_id"],
            "tenant_id": sample_token_data["tenant_id"],
            "role": sample_token_data["role"],
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=1)).timestamp())
        }
        
        # Sign with wrong key
        invalid_token = jwt.encode(
            payload,
            wrong_private_pem,
            algorithm="RS256"
        )
        
        with pytest.raises(AuthenticationError) as exc_info:
            jwt_handler.validate_jwt(invalid_token)
        
        assert exc_info.value.code == "INVALID_TOKEN"
        assert "signature" in exc_info.value.message.lower() or "invalid" in exc_info.value.message.lower()
    
    def test_validate_jwt_rejects_malformed_token(self, jwt_handler):
        """Test that validate_jwt rejects malformed tokens"""
        malformed_tokens = [
            "not.a.jwt",
            "invalid_token",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid",
            "",
            "a.b"
        ]
        
        for malformed_token in malformed_tokens:
            with pytest.raises(AuthenticationError) as exc_info:
                jwt_handler.validate_jwt(malformed_token)
            
            assert exc_info.value.code == "INVALID_TOKEN"
    
    def test_validate_jwt_rejects_token_missing_required_fields(self, jwt_handler):
        """Test that validate_jwt rejects tokens missing required fields"""
        now = datetime.utcnow()
        
        # Token missing tenant_id but with far future expiration
        incomplete_payload = {
            "user_id": "user_123",
            "role": "admin",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(days=365)).timestamp())  # 1 year expiration
        }
        
        incomplete_token = jwt.encode(
            incomplete_payload,
            jwt_handler.private_key,
            algorithm="RS256"
        )
        
        with pytest.raises(AuthenticationError) as exc_info:
            jwt_handler.validate_jwt(incomplete_token)
        
        # The error should be about missing fields
        assert exc_info.value.code == "INVALID_TOKEN"
        assert "missing" in exc_info.value.message.lower() or "tenant_id" in exc_info.value.message.lower()


class TestJWTRoundTrip:
    """Test JWT generation and validation round-trip"""
    
    def test_jwt_round_trip_preserves_data(self, jwt_handler, sample_token_data):
        """Test that generating and validating a token preserves all data"""
        # Create token with far future expiration
        now = datetime.utcnow()
        payload = {
            "user_id": sample_token_data["user_id"],
            "tenant_id": sample_token_data["tenant_id"],
            "role": sample_token_data["role"],
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(days=365)).timestamp())
        }
        
        token = jwt.encode(
            payload,
            jwt_handler.private_key,
            algorithm="RS256"
        )
        
        # Validate token
        validated_payload = jwt_handler.validate_jwt(token)
        
        # Verify all data is preserved
        assert validated_payload.user_id == sample_token_data["user_id"]
        assert validated_payload.tenant_id == sample_token_data["tenant_id"]
        assert validated_payload.role == sample_token_data["role"]
        assert validated_payload.exp > validated_payload.iat
    
    def test_jwt_round_trip_with_multiple_tenants(self, jwt_handler):
        """Test round-trip with different tenant IDs"""
        tenants = [
            {"user_id": "user_1", "tenant_id": "tenant_a", "role": "admin"},
            {"user_id": "user_2", "tenant_id": "tenant_b", "role": "developer"},
            {"user_id": "user_3", "tenant_id": "tenant_c", "role": "read_only"}
        ]
        
        now = datetime.utcnow()
        
        for tenant_data in tenants:
            payload = {
                "user_id": tenant_data["user_id"],
                "tenant_id": tenant_data["tenant_id"],
                "role": tenant_data["role"],
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(days=365)).timestamp())
            }
            
            token = jwt.encode(
                payload,
                jwt_handler.private_key,
                algorithm="RS256"
            )
            
            validated_payload = jwt_handler.validate_jwt(token)
            
            assert validated_payload.user_id == tenant_data["user_id"]
            assert validated_payload.tenant_id == tenant_data["tenant_id"]
            assert validated_payload.role == tenant_data["role"]


class TestTokenPayload:
    """Test TokenPayload class"""
    
    def test_token_payload_to_dict(self):
        """Test TokenPayload to_dict method"""
        payload = TokenPayload(
            tenant_id="tenant_123",
            user_id="user_456",
            role="admin",
            exp=1234567890,
            iat=1234564290
        )
        
        payload_dict = payload.to_dict()
        
        assert payload_dict["tenant_id"] == "tenant_123"
        assert payload_dict["user_id"] == "user_456"
        assert payload_dict["role"] == "admin"
        assert payload_dict["exp"] == 1234567890
        assert payload_dict["iat"] == 1234564290
    
    def test_token_payload_from_dict(self):
        """Test TokenPayload from_dict method"""
        data = {
            "tenant_id": "tenant_123",
            "user_id": "user_456",
            "role": "admin",
            "exp": 1234567890,
            "iat": 1234564290
        }
        
        payload = TokenPayload.from_dict(data)
        
        assert payload.tenant_id == "tenant_123"
        assert payload.user_id == "user_456"
        assert payload.role == "admin"
        assert payload.exp == 1234567890
        assert payload.iat == 1234564290
    
    def test_token_payload_round_trip(self):
        """Test TokenPayload to_dict and from_dict round-trip"""
        original = TokenPayload(
            tenant_id="tenant_xyz",
            user_id="user_abc",
            role="developer",
            exp=9876543210,
            iat=9876539610
        )
        
        # Convert to dict and back
        payload_dict = original.to_dict()
        restored = TokenPayload.from_dict(payload_dict)
        
        assert restored.tenant_id == original.tenant_id
        assert restored.user_id == original.user_id
        assert restored.role == original.role
        assert restored.exp == original.exp
        assert restored.iat == original.iat


class TestAuthenticationError:
    """Test AuthenticationError exception"""
    
    def test_authentication_error_attributes(self):
        """Test that AuthenticationError has correct attributes"""
        error = AuthenticationError("TEST_CODE", "Test message")
        
        assert error.code == "TEST_CODE"
        assert error.message == "Test message"
        assert str(error) == "Test message"
    
    def test_authentication_error_can_be_raised(self):
        """Test that AuthenticationError can be raised and caught"""
        with pytest.raises(AuthenticationError) as exc_info:
            raise AuthenticationError("INVALID_TOKEN", "Token is invalid")
        
        assert exc_info.value.code == "INVALID_TOKEN"
        assert exc_info.value.message == "Token is invalid"
