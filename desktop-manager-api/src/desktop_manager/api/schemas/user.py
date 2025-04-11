from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserBase(BaseModel):
    """Base schema for user data."""

    username: str = Field(..., description="Unique username", min_length=3, max_length=255)
    email: EmailStr | None = Field(None, description="User's email address")
    organization: str | None = Field(None, description="User's organization")
    is_admin: bool = Field(default=False, description="Whether the user has admin privileges")


class OIDCUserInfo(BaseModel):
    """Schema for OIDC user information."""

    sub: str = Field(..., description="OIDC subject identifier")
    given_name: str | None = Field(None, description="User's given name")
    family_name: str | None = Field(None, description="User's family name")
    name: str | None = Field(None, description="User's full name")
    locale: str | None = Field(None, description="User's locale preference")
    email_verified: bool = Field(default=False, description="Whether email has been verified")
    email: EmailStr = Field(..., description="User's email address")
    organization: str | None = Field(None, description="User's organization")


class SocialAuthAssociation(BaseModel):
    """Schema for social auth association data."""

    provider: str = Field(..., description="Auth provider (e.g., 'oidc')")
    provider_user_id: str = Field(..., description="User ID from the provider")
    provider_name: str | None = Field(None, description="Name of the provider")
    extra_data: dict[str, Any] | None = Field(default_factory=dict, description="Additional provider data")

    model_config = ConfigDict(from_attributes=True)


class PKCEState(BaseModel):
    """Schema for PKCE state data."""

    state: str = Field(..., description="Random state string")
    code_verifier: str = Field(..., description="PKCE code verifier")
    expires_at: datetime = Field(..., description="When the state expires")

    model_config = ConfigDict(from_attributes=True)


class UserCreate(UserBase):
    """Schema for creating a new user."""

    sub: str = Field(..., description="OIDC subject identifier")
    oidc_data: OIDCUserInfo | None = Field(None, description="OIDC user information")


class UserResponse(UserBase):
    """Schema for user response data."""

    id: int = Field(..., description="Unique identifier of the user")
    created_at: datetime = Field(..., description="Timestamp of user creation")
    sub: str | None = Field(None, description="OIDC subject identifier")
    given_name: str | None = Field(None, description="User's given name")
    family_name: str | None = Field(None, description="User's family name")
    name: str | None = Field(None, description="User's full name")
    locale: str | None = Field(None, description="User's locale preference")
    email_verified: bool = Field(default=False, description="Whether email has been verified")
    last_login: datetime | None = Field(None, description="Last login timestamp")
    social_auth: list[SocialAuthAssociation] = Field(default_factory=list, description="Social auth associations")

    model_config = ConfigDict(from_attributes=True)


class UserList(BaseModel):
    """Schema for list of users response."""

    users: list[UserResponse] = Field(default_factory=list, description="List of users")


class UserLogin(BaseModel):
    """Schema for user login (deprecated - OIDC login is now required)."""

    username: str = Field(..., description="Username for login")


class UserUpdate(BaseModel):
    """Schema for updating user data."""

    username: str | None = Field(None, min_length=3, max_length=255)
    email: EmailStr | None = Field(None, description="User's email address")
    organization: str | None = Field(None, description="User's organization")
    is_admin: bool | None = None
    oidc_data: OIDCUserInfo | None = None


class TokenResponse(BaseModel):
    """Schema for authentication token response."""

    token: str = Field(..., description="JWT authentication token")
    is_admin: bool = Field(..., description="Whether the user has admin privileges")
    username: str = Field(..., description="Username of the authenticated user")
    email: EmailStr = Field(..., description="User's email address")
    organization: str | None = Field(None, description="User's organization")
    sub: str | None = Field(None, description="OIDC subject identifier")


class UserInDB(UserBase):
    """Schema for user in database."""

    id: int
    created_at: datetime
    sub: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    name: str | None = None
    locale: str | None = None
    email_verified: bool = False
    last_login: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class User(UserBase):
    """Schema for user response."""

    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
