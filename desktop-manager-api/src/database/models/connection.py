"""SQLAlchemy model for connections.

This module defines the Connection model for database operations.
"""

from datetime import datetime

from models.base import Base
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func


class Connection(Base):
    """SQLAlchemy model representing a desktop connection.

    This model stores information about desktop connections, including their
    unique identifiers, names, creation timestamps, creators, and associated
    Guacamole connection IDs.

    Attributes:
        id (int): Primary key, auto-incrementing identifier
        name (str): Unique name of the connection
        created_at (datetime): Timestamp of when the connection was created
        created_by (str): Username of the user who created the connection
        guacamole_connection_id (str): ID of the corresponding Guacamole connection
        is_stopped (bool): Whether the connection is currently stopped
        persistent_home (bool): Whether the home directory is persistent
        desktop_configuration_id (int): ID of the desktop configuration used
    """

    __tablename__ = "connections"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    name: str = Column(String(255), unique=True, index=True, nullable=False)
    created_at: datetime = Column(DateTime, server_default=func.now(), nullable=False)
    created_by: str = Column(String(255), ForeignKey("users.username", ondelete="CASCADE"), nullable=False)
    guacamole_connection_id: str = Column(String(255), nullable=False)
    is_stopped: bool = Column(Boolean, default=False, nullable=False)
    persistent_home: bool = Column(Boolean, default=True, nullable=False)
    desktop_configuration_id: int = Column(Integer, ForeignKey("desktop_configurations.id"), nullable=True)

    # Relationship to storage PVCs through the mapping table
    # Using viewonly=False to ensure both sides of the relationship can modify
    pvcs = relationship("StoragePVC", secondary="connection_pvcs", back_populates="connections", viewonly=False)

    # Relationship to desktop configuration
    desktop_configuration = relationship("DesktopConfiguration", back_populates="connections")

    # Relationship to user who created the connection
    creator = relationship("User", foreign_keys=[created_by], back_populates="connections")

    def __repr__(self) -> str:
        """Return string representation of the Connection."""
        return f"<Connection(name={self.name}, created_by={self.created_by})>"
