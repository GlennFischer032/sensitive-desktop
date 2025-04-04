"""Pydantic schemas for connection operations."""

from datetime import datetime
import re

from pydantic import BaseModel, Field, field_validator


class ConnectionBase(BaseModel):
    """Base connection schema with common attributes."""

    name: str = Field(..., description="Unique name of the connection")
    guacamole_connection_id: str = Field(
        ..., description="ID of the corresponding Guacamole connection"
    )


class ConnectionCreate(ConnectionBase):
    """Schema for creating a new connection."""

    pass


class ConnectionUpdate(BaseModel):
    """Schema for updating an existing connection."""

    name: str | None = Field(None, description="New name for the connection")
    guacamole_connection_id: str | None = Field(None, description="New Guacamole connection ID")


class ConnectionResponse(ConnectionBase):
    """Schema for connection responses."""

    id: int = Field(..., description="Unique identifier of the connection")
    created_by: str = Field(..., description="Username of the user who created the connection")
    created_at: datetime = Field(..., description="Timestamp when the connection was created")

    class Config:
        """Pydantic configuration."""

        from_attributes = True


class ConnectionList(BaseModel):
    """Schema for list of connections response."""

    connections: list[ConnectionResponse] = Field(
        default_factory=list, description="List of connections"
    )


class ConnectionScaleUp(BaseModel):
    """Schema for scaling up a connection."""

    name: str = Field(
        ...,
        description="Name for the new connection",
        min_length=1,
        max_length=12,
        pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        """Validate the connection name.

        The name must:
        - Not be empty or just whitespace
        - Start and end with an alphanumeric character
        - Contain only lowercase letters, numbers, and hyphens
        - Not exceed max length (which will be further constrained to account for UUID suffix)
        - Match the Kubernetes DNS-1123 subdomain pattern
        """
        v = v.strip().lower()

        if not v:
            raise ValueError("Name cannot be empty or just whitespace")

        # Validate against Kubernetes naming pattern
        pattern = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")
        if not pattern.match(v):
            raise ValueError(
                "Name must start and end with an alphanumeric character and "
                "contain only lowercase letters, numbers, and hyphens"
            )

        return v


class ConnectionScaleDown(BaseModel):
    """Schema for scaling down a connection."""

    name: str = Field(
        ...,
        description="Name of the connection to scale down",
        min_length=1,
        max_length=255,
    )
