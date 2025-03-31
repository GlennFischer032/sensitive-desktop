"""Pydantic schemas for desktop configurations."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class DesktopConfigurationBase(BaseModel):
    """Base schema for desktop configurations."""

    name: str = Field(..., description="Name of the desktop configuration")
    description: Optional[str] = Field(None, description="Description of the desktop configuration")
    image: str = Field(..., description="Docker image for the desktop environment")
    is_public: bool = Field(
        False, description="Whether the configuration is available to all users"
    )
    min_cpu: int = Field(1, description="Minimum number of CPU cores")
    max_cpu: int = Field(4, description="Maximum number of CPU cores")
    min_ram: str = Field("4096Mi", description="Minimum RAM allocation (format: number + Mi/Gi)")
    max_ram: str = Field("16384Mi", description="Maximum RAM allocation (format: number + Mi/Gi)")


class DesktopConfigurationCreate(DesktopConfigurationBase):
    """Schema for creating desktop configurations."""

    pass


class DesktopConfigurationUpdate(BaseModel):
    """Schema for updating desktop configurations."""

    name: Optional[str] = Field(None, description="Name of the desktop configuration")
    description: Optional[str] = Field(None, description="Description of the desktop configuration")
    image: Optional[str] = Field(None, description="Docker image for the desktop environment")
    is_public: Optional[bool] = Field(
        None, description="Whether the configuration is available to all users"
    )
    min_cpu: Optional[int] = Field(None, description="Minimum number of CPU cores")
    max_cpu: Optional[int] = Field(None, description="Maximum number of CPU cores")
    min_ram: Optional[str] = Field(
        None, description="Minimum RAM allocation (format: number + Mi/Gi)"
    )
    max_ram: Optional[str] = Field(
        None, description="Maximum RAM allocation (format: number + Mi/Gi)"
    )


class DesktopConfigurationInDB(DesktopConfigurationBase):
    """Schema for desktop configurations as stored in the database."""

    id: int
    created_at: datetime
    created_by: str

    class Config:
        """Pydantic configuration."""

        from_attributes = True  # For SQLAlchemy compatibility


class DesktopConfigurationAccessBase(BaseModel):
    """Base schema for desktop configuration access."""

    desktop_configuration_id: int
    username: str


class DesktopConfigurationAccessCreate(DesktopConfigurationAccessBase):
    """Schema for creating desktop configuration access."""

    pass


class DesktopConfigurationAccessInDB(DesktopConfigurationAccessBase):
    """Schema for desktop configuration access as stored in the database."""

    id: int
    created_at: datetime

    class Config:
        """Pydantic configuration."""

        from_attributes = True  # For SQLAlchemy compatibility


class DesktopConfigurationWithAccess(DesktopConfigurationInDB):
    """Schema for desktop configurations with access information."""

    allowed_users: List[str] = Field(
        [], description="Usernames of users with access to this configuration"
    )
