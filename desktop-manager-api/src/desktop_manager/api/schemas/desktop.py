from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from datetime import datetime

class DesktopBase(BaseModel):
    name: str = Field(..., min_length=3, max_length=100)

class DesktopCreate(DesktopBase):
    pass

class DesktopUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=3, max_length=100)
    is_active: Optional[bool] = None

class Desktop(DesktopBase):
    id: int
    user_id: int
    connection_id: str
    ip_address: Optional[str] = None
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)

class DesktopInDB(Desktop):
    vnc_password: str
    
    model_config = ConfigDict(from_attributes=True) 