"""SQLAlchemy model for connections.

This module defines the Connection model for database operations.
"""

from datetime import datetime

from schemas.base import Base
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from utils.encryption import decrypt_password, encrypt_password


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
        hostname (str): Hostname of the connection
        port (str): Port of the connection
        is_stopped (bool): Whether the connection is currently stopped
        persistent_home (bool): Whether the home directory is persistent
        desktop_configuration_id (int): ID of the desktop configuration used
        encrypted_password (str): Encrypted password for VNC connection
    """

    __tablename__ = "connections"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    name: str = Column(String(255), unique=True, index=True, nullable=False)
    created_at: datetime = Column(DateTime, server_default=func.now(), nullable=False)
    created_by: str = Column(String(255), ForeignKey("users.username", ondelete="CASCADE"), nullable=False)
    hostname: str = Column(String(255), nullable=False)
    port: str = Column(String(255), nullable=False)
    encrypted_password: str = Column(String(255), nullable=True)
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

    def set_password(self, password: str) -> None:
        """Set the connection password, encrypting it for storage.

        Args:
            password: The plaintext password to encrypt and store
        """
        self.encrypted_password = encrypt_password(password)

    def get_password(self) -> str:
        """Get the decrypted connection password.

        Returns:
            The decrypted plaintext password, or None if no password is set
        """
        return decrypt_password(self.encrypted_password)

    def __repr__(self) -> str:
        """Return string representation of the Connection."""
        return f"<Connection(name={self.name}, created_by={self.created_by})>"
