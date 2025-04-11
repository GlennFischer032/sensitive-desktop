"""SQLAlchemy models for desktop configurations.

This module defines the DesktopConfiguration and DesktopConfigurationAccess models for database operations.
"""

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from desktop_manager.api.models.base import Base


class DesktopConfiguration(Base):
    """SQLAlchemy model representing a desktop configuration.

    This model stores information about desktop configurations, including their
    unique identifiers, names, descriptions, and associated Docker images.

    Attributes:
        id (int): Primary key, auto-incrementing identifier
        name (str): Unique name of the configuration
        description (str): Detailed description of the configuration
        image (str): Docker image for the desktop environment
        created_at (datetime): Timestamp of when the configuration was created
        created_by (str): Username of the user who created the configuration
        is_public (bool): Whether the configuration is available to all users
        min_cpu (int): Minimum number of CPU cores (default: 1)
        max_cpu (int): Maximum number of CPU cores (default: 4)
        min_ram (str): Minimum RAM allocation (default: '4096Mi')
        max_ram (str): Maximum RAM allocation (default: '16384Mi')
    """

    __tablename__ = "desktop_configurations"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    name: str = Column(String(255), unique=True, index=True, nullable=False)
    description: str = Column(Text, nullable=True)
    image: str = Column(String(255), nullable=False)
    created_at: datetime = Column(DateTime, server_default=func.now())
    created_by: str = Column(String(255), ForeignKey("users.username", ondelete="CASCADE"))
    is_public: bool = Column(Boolean, default=False)
    min_cpu: int = Column(Integer, default=1)
    max_cpu: int = Column(Integer, default=4)
    min_ram: str = Column(String(10), default="4096Mi")
    max_ram: str = Column(String(10), default="16384Mi")

    # Relationships
    creator = relationship("User", back_populates="desktop_configurations")
    user_access = relationship(
        "DesktopConfigurationAccess", back_populates="desktop_configuration", cascade="all, delete-orphan"
    )
    connections = relationship("Connection", back_populates="desktop_configuration")

    def __repr__(self) -> str:
        """Return string representation of the DesktopConfiguration."""
        return f"<DesktopConfiguration(name={self.name}, image={self.image})>"


class DesktopConfigurationAccess(Base):
    """SQLAlchemy model representing desktop configuration access control.

    This model stores information about which users have access to which
    desktop configurations.

    Attributes:
        id (int): Primary key, auto-incrementing identifier
        desktop_configuration_id (int): ID of the desktop configuration
        username (str): Username of the user with access
        created_at (datetime): Timestamp of when the access was granted
    """

    __tablename__ = "desktop_configuration_access"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    desktop_configuration_id: int = Column(
        Integer, ForeignKey("desktop_configurations.id", ondelete="CASCADE"), nullable=False
    )
    username: str = Column(String(255), ForeignKey("users.username", ondelete="CASCADE"), nullable=False)
    created_at: datetime = Column(DateTime, server_default=func.now())

    # Relationships
    desktop_configuration = relationship("DesktopConfiguration", back_populates="user_access")
    user = relationship("User", back_populates="desktop_configuration_access")

    def __repr__(self) -> str:
        """Return string representation of the DesktopConfigurationAccess."""
        return (
            f"<DesktopConfigurationAccess(desktop_configuration_id={self.desktop_configuration_id}, "
            f"username={self.username})>"
        )
