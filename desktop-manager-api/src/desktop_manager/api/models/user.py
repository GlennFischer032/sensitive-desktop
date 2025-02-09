from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
from typing import List, Optional
from desktop_manager.api.models.base import Base

class User(Base):
    """
    SQLAlchemy model representing a user in the system.
    
    This model stores information about users, including their authentication
    credentials, admin status, and creation timestamp. It also maintains
    relationships with their created connections.
    
    Attributes:
        id (int): Primary key, auto-incrementing identifier
        username (str): Unique username for the user
        password_hash (str): Hashed password for authentication
        is_admin (bool): Whether the user has administrator privileges
        created_at (datetime): Timestamp of when the user was created
        connections (List[Connection]): List of connections created by this user
    """
    __tablename__: str = "users"
    
    id: int = Column(Integer, primary_key=True, index=True)
    username: str = Column(String(255), unique=True, index=True, nullable=False)
    password_hash: str = Column(String(255), nullable=False)
    is_admin: bool = Column(Boolean, default=False)
    created_at: datetime = Column(DateTime, server_default=func.now())
    
    # Relationship to connections created by this user
    connections = relationship("Connection", back_populates="creator", cascade="all, delete-orphan")
    
    def __repr__(self) -> str:
        """Return string representation of the User."""
        return f"<User {self.username}>" 