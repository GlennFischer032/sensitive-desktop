from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
from typing import Optional
from .base import Base

class Desktop(Base):
    __tablename__: str = "desktops"
    
    id: int = Column(Integer, primary_key=True, index=True)
    name: str = Column(String(100), nullable=False)
    user_id: int = Column(Integer, ForeignKey("users.id"), nullable=False)
    connection_id: str = Column(String(100), unique=True, nullable=False)
    ip_address: str = Column(String(45), nullable=True)  # IPv6 addresses can be up to 45 chars
    vnc_password: str = Column(String(100), nullable=False)
    is_active: bool = Column(Boolean, default=True)
    created_at: datetime = Column(DateTime(timezone=True), server_default=func.now())
    updated_at: datetime = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    user = relationship("User", back_populates="desktops")
    
    def __repr__(self) -> str:
        return f"<Desktop {self.name} ({self.ip_address})>" 