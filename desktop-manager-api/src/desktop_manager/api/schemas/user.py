from datetime import datetime
from pydantic import BaseModel, Field, validator, ConfigDict
from typing import Optional, List

class UserBase(BaseModel):
    """Base schema for user data."""
    username: str = Field(..., description="Unique username", min_length=3, max_length=255)
    is_admin: bool = Field(default=False, description="Whether the user has admin privileges")

class UserCreate(UserBase):
    """Schema for creating a new user."""
    password: str = Field(
        ..., 
        description="User's password", 
        min_length=8,
        max_length=255
    )

    @validator('password')
    def validate_password(cls, v):
        """Validate password strength."""
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
    password: Optional[str] = Field(None, min_length=8)
    is_admin: Optional[bool] = None

    @validator('password')
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

class UserInDB(UserBase):
    """Schema for user in database."""
    id: int
    created_at: datetime
    password_hash: str
    
    model_config = ConfigDict(from_attributes=True)

class User(UserBase):
    """Schema for user response."""
    id: int
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True) 