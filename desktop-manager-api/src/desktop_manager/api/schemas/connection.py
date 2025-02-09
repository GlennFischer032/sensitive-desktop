from datetime import datetime
from pydantic import BaseModel, Field, validator
from typing import Optional

class ConnectionBase(BaseModel):
    """Base schema for connection data."""
    name: str = Field(..., description="Unique name of the connection", min_length=1, max_length=255)
    created_by: str = Field(..., description="Username of the connection creator")
    guacamole_connection_id: str = Field(..., description="ID of the corresponding Guacamole connection")

class ConnectionCreate(ConnectionBase):
    """Schema for creating a new connection."""
    pass

class ConnectionResponse(ConnectionBase):
    """Schema for connection response data."""
    id: int = Field(..., description="Unique identifier of the connection")
    created_at: datetime = Field(..., description="Timestamp of connection creation")

    class Config:
        from_attributes = True

class ConnectionList(BaseModel):
    """Schema for list of connections response."""
    connections: list[ConnectionResponse] = Field(default_factory=list, description="List of connections")

class ConnectionScaleUp(BaseModel):
    """Schema for scaling up a connection."""
    name: str = Field(..., description="Name for the new connection", min_length=1, max_length=255)

    @validator('name')
    def validate_name(cls, v):
        if not v.strip():
            raise ValueError("Name cannot be empty or just whitespace")
        return v.strip()

class ConnectionScaleDown(BaseModel):
    """Schema for scaling down a connection."""
    name: str = Field(..., description="Name of the connection to scale down", min_length=1, max_length=255) 