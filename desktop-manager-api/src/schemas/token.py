"""API Token models and schemas.

This module defines the models for API tokens used for admin authentication.
"""

from datetime import datetime

from pydantic import BaseModel, Field


class TokenCreate(BaseModel):
    """Schema for creating a new API token."""

    name: str = Field(..., description="Name for the token", min_length=1, max_length=255)
    description: str | None = Field(None, description="Optional description for the token")
    expires_in_days: int = Field(30, description="Number of days until token expiration", ge=1, le=365)


class Token(BaseModel):
    """Schema for an API token response."""

    id: int = Field(..., description="Token database ID")
    token_id: str = Field(..., description="Unique token identifier")
    name: str = Field(..., description="Token name")
    description: str | None = Field(None, description="Token description")
    created_at: datetime = Field(..., description="Token creation timestamp")
    expires_at: datetime = Field(..., description="Token expiration timestamp")
    created_by: str = Field(..., description="Username of token creator")
    last_used: datetime | None = Field(None, description="Timestamp of last token usage")
    revoked: bool = Field(False, description="Whether the token has been revoked")
    revoked_at: datetime | None = Field(None, description="Timestamp when token was revoked")


class TokenResponse(BaseModel):
    """Schema for a newly created token response that includes the actual JWT token."""

    token: str = Field(..., description="JWT token value for authentication")
    token_id: str = Field(..., description="Unique token identifier")
    name: str = Field(..., description="Token name")
    expires_at: datetime = Field(..., description="Token expiration timestamp")
    created_by: str = Field(..., description="Username of token creator")
