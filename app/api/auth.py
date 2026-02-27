"""
Authentication API Endpoints

Provides endpoints for user login, API key management.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID

from app.auth import auth_service
from app.database import get_db


router = APIRouter(prefix="/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 3600


class APIKeyCreateRequest(BaseModel):
    name: str
    role: str


class APIKeyResponse(BaseModel):
    id: UUID
    key: str  # Only returned on creation
    key_prefix: str
    name: str
    role: str


@router.post("/login", response_model=LoginResponse)
async def login(
    credentials: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Authenticate user and obtain JWT token.
    
    The token must be included in the Authorization header for subsequent requests.
    Token expires after 1 hour.
    """
    user = await auth_service.authenticate_user(
        db=db,
        email=credentials.email,
        password=credentials.password
    )
    
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Generate JWT token
    token = auth_service.generate_token(
        user_id=str(user.id),
        tenant_id="tenant_default",
        role=user.role
    )
    
    return LoginResponse(access_token=token)


@router.post("/api-keys", response_model=APIKeyResponse)
async def create_api_key(
    request: APIKeyCreateRequest,
    db: AsyncSession = Depends(get_db)
):
    """Create a new API key for the authenticated tenant."""
    api_key, full_key = await auth_service.api_key_manager.create_api_key(
        db=db,
        tenant_id="tenant_default",
        role=request.role,
        name=request.name
    )
    
    return APIKeyResponse(
        id=api_key.id,
        key=full_key,
        key_prefix=api_key.key_prefix,
        name=api_key.name,
        role=api_key.role
    )
