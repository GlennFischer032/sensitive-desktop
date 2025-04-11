"""SQLAlchemy models for storage PVCs.

This module defines the StoragePVC, ConnectionPVCMap, and StoragePVCAccess models for database operations.
"""

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.sql import func

from desktop_manager.api.models.base import Base


class StoragePVC(Base):
    """SQLAlchemy model for Persistent Volume Claims.

    This model stores information about Kubernetes Persistent Volume Claims.

    Attributes:
        id (int): Primary key, auto-incrementing identifier
        name (str): PVC name in Kubernetes
        namespace (str): Kubernetes namespace
        size (str): Storage size (e.g. '10Gi')
        is_public (bool): Whether the PVC is publicly accessible
        created_at (datetime): When the PVC was created
        created_by (str): Username of the creator
        status (str): PVC status (e.g. 'Pending', 'Bound')
        last_updated (datetime): When the PVC was last updated
    """

    __tablename__ = "storage_pvcs"

    id: int = Column(Integer, primary_key=True)
    name: str = Column(String(255), nullable=False, unique=True)
    namespace: str = Column(String(255), nullable=False)
    size: str = Column(String(50), nullable=False)
    is_public: bool = Column(Boolean, default=False, nullable=False)
    created_at: datetime = Column(DateTime, server_default=func.now(), nullable=False)
    created_by: str = Column(String(255), ForeignKey("users.username", ondelete="CASCADE"), nullable=False)
    status: str = Column(String(50), default="Pending", nullable=False)
    last_updated: datetime = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    def __repr__(self) -> str:
        """Return string representation of the StoragePVC."""
        return f"<StoragePVC {self.name} ({self.status})>"


class ConnectionPVCMap(Base):
    """SQLAlchemy model for Connection-PVC mappings.

    This model stores relationships between connections and PVCs.

    Attributes:
        id (int): Primary key, auto-incrementing identifier
        connection_id (int): Connection ID
        pvc_id (int): PVC ID
        created_at (datetime): When the mapping was created
    """

    __tablename__ = "connection_pvcs"

    id: int = Column(Integer, primary_key=True)
    connection_id: int = Column(Integer, ForeignKey("connections.id", ondelete="CASCADE"), nullable=False)
    pvc_id: int = Column(Integer, ForeignKey("storage_pvcs.id", ondelete="CASCADE"), nullable=False)
    created_at: datetime = Column(DateTime, server_default=func.now(), nullable=False)

    def __repr__(self) -> str:
        """Return string representation of the ConnectionPVCMap."""
        return f"<ConnectionPVCMap {self.connection_id}-{self.pvc_id}>"


class StoragePVCAccess(Base):
    """SQLAlchemy model for PVC access control.

    This model stores user access permissions for PVCs.

    Attributes:
        id (int): Primary key, auto-incrementing identifier
        pvc_id (int): PVC ID
        username (str): Username with access
        created_at (datetime): When the access was granted
    """

    __tablename__ = "storage_pvc_access"

    id: int = Column(Integer, primary_key=True)
    pvc_id: int = Column(Integer, ForeignKey("storage_pvcs.id", ondelete="CASCADE"), nullable=False)
    username: str = Column(String(255), ForeignKey("users.username", ondelete="CASCADE"), nullable=False)
    created_at: datetime = Column(DateTime, server_default=func.now(), nullable=False)

    def __repr__(self) -> str:
        """Return string representation of the StoragePVCAccess."""
        return f"<StoragePVCAccess {self.pvc_id}-{self.username}>"
