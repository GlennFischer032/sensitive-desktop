from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from desktop_manager.api.models.base import Base


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
        target_host (str): Hostname or IP address of the remote desktop
        target_port (int): Port number for the connection
        password (str): Password for the connection
        protocol (str): Protocol used for the connection (e.g., vnc, rdp)
    """

    __tablename__ = "connections"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    name: str = Column(String(255), unique=True, index=True, nullable=False)
    created_at: datetime = Column(DateTime, default=datetime.utcnow)
    created_by: str = Column(String(255), ForeignKey("users.username", ondelete="CASCADE"))
    guacamole_connection_id: str = Column(String(255), nullable=False)
    target_host: str = Column(String(255), nullable=True)
    target_port: int = Column(Integer, nullable=True)
    password: str = Column(String(255), nullable=True)
    protocol: str = Column(String(50), nullable=True, default="vnc")

    # Relationship to user who created the connection
    creator = relationship("User", back_populates="connections")

    def __repr__(self) -> str:
        """Return string representation of the Connection."""
        return f"<Connection(name={self.name}, created_by={self.created_by})>"
