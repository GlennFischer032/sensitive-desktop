from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class UserBase(BaseModel):
    """Base schema for user data."""

    username: str = Field(..., description="Unique username", min_length=3, max_length=255)
    email: EmailStr = Field(..., description="User's email address")
    organization: Optional[str] = Field(None, description="User's organization")
    is_admin: bool = Field(default=False, description="Whether the user has admin privileges")


class OIDCUserInfo(BaseModel):
    """Schema for OIDC user information."""

    sub: str = Field(..., description="OIDC subject identifier")
    given_name: Optional[str] = Field(None, description="User's given name")
    family_name: Optional[str] = Field(None, description="User's family name")
    locale: Optional[str] = Field(None, description="User's locale preference")
    email_verified: bool = Field(default=False, description="Whether email has been verified")
    email: EmailStr = Field(..., description="User's email address")
    organization: Optional[str] = Field(None, description="User's organization")


class SocialAuthAssociation(BaseModel):
    """Schema for social auth association data."""

    provider: str = Field(..., description="Auth provider (e.g., 'oidc')")
    provider_user_id: str = Field(..., description="User ID from the provider")
    provider_name: Optional[str] = Field(None, description="Name of the provider")
    extra_data: Optional[Dict[str, Any]] = Field(
        default_factory=dict, description="Additional provider data"
    )

    model_config = ConfigDict(from_attributes=True)


class PKCEState(BaseModel):
    """Schema for PKCE state data."""

    state: str = Field(..., description="Random state string")
    code_verifier: str = Field(..., description="PKCE code verifier")
    expires_at: datetime = Field(..., description="When the state expires")

    model_config = ConfigDict(from_attributes=True)


class UserCreate(UserBase):
    """Schema for creating a new user."""

    password: Optional[str] = Field(
        None,
        description="User's password (optional for OIDC users)",
        min_length=8,
        max_length=255,
    )
    sub: Optional[str] = Field(None, description="OIDC subject identifier")
    oidc_data: Optional[OIDCUserInfo] = Field(None, description="OIDC user information")

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        """Validate password strength if provided."""
        if v is not None:
            if not any(char.isupper() for char in v):
                raise ValueError("Password must contain at least one uppercase letter")
            if not any(char.islower() for char in v):
                raise ValueError("Password must contain at least one lowercase letter")
            if not any(char.isdigit() for char in v):
                raise ValueError("Password must contain at least one number")
        return v


class UserResponse(UserBase):
    """Schema for user response data."""

    id: int = Field(..., description="Unique identifier of the user")
    created_at: datetime = Field(..., description="Timestamp of user creation")
    sub: Optional[str] = Field(None, description="OIDC subject identifier")
    given_name: Optional[str] = Field(None, description="User's given name")
    family_name: Optional[str] = Field(None, description="User's family name")
    locale: Optional[str] = Field(None, description="User's locale preference")
    email_verified: bool = Field(default=False, description="Whether email has been verified")
    last_login: Optional[datetime] = Field(None, description="Last login timestamp")
    social_auth: List[SocialAuthAssociation] = Field(
        default_factory=list, description="Social auth associations"
    )

    model_config = ConfigDict(from_attributes=True)


class UserList(BaseModel):
    """Schema for list of users response."""

    users: List[UserResponse] = Field(default_factory=list, description="List of users")


class UserLogin(BaseModel):
    """Schema for user login."""

    username: str = Field(..., description="Username for login")
    password: str = Field(..., description="Password for login")


class UserUpdate(BaseModel):
    """Schema for updating user data."""

    username: Optional[str] = Field(None, min_length=3, max_length=255)
    email: Optional[EmailStr] = Field(None, description="User's email address")
    organization: Optional[str] = Field(None, description="User's organization")
    password: Optional[str] = Field(None, min_length=8)
    is_admin: Optional[bool] = None
    oidc_data: Optional[OIDCUserInfo] = None

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        """Validate password strength if provided."""
        if v is not None:
            if len(v) < 8:
                raise ValueError("Password must be at least 8 characters long")
            if not any(char.isupper() for char in v):
                raise ValueError("Password must contain at least one uppercase letter")
            if not any(char.islower() for char in v):
                raise ValueError("Password must contain at least one lowercase letter")
            if not any(char.isdigit() for char in v):
                raise ValueError("Password must contain at least one number")
        return v


class TokenResponse(BaseModel):
    """Schema for authentication token response."""

    token: str = Field(..., description="JWT authentication token")
    is_admin: bool = Field(..., description="Whether the user has admin privileges")
    username: str = Field(..., description="Username of the authenticated user")
    email: EmailStr = Field(..., description="User's email address")
    organization: Optional[str] = Field(None, description="User's organization")
    sub: Optional[str] = Field(None, description="OIDC subject identifier")


class UserInDB(UserBase):
    """Schema for user in database."""

    id: int
    created_at: datetime
    password_hash: Optional[str]
    sub: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    locale: Optional[str] = None
    email_verified: bool = False
    last_login: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class User(UserBase):
    """Schema for user response."""

    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
