"""Storage PVC model module for desktop-manager-api.

This module provides models for managing Persistent Volume Claims (PVCs) for desktop storage.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from desktop_manager.api.models.base import APIModel


class StoragePVCBase(BaseModel):
    """Base model for storage PVC."""

    name: str = Field(..., description="PVC name")
    namespace: str = Field(..., description="Kubernetes namespace")
    size: str = Field(..., description="Storage size (e.g. '10Gi')")
    is_public: bool = Field(False, description="Whether the PVC is publicly accessible")


class StoragePVCCreate(StoragePVCBase):
    """Model for creating a new storage PVC."""

    created_by: Optional[str] = Field(None, description="Username of the creator")


class StoragePVCUpdate(BaseModel):
    """Model for updating a storage PVC."""

    status: Optional[str] = Field(None, description="PVC status")
    last_updated: Optional[datetime] = Field(None, description="Last updated timestamp")


class StoragePVC(APIModel, StoragePVCBase):
    """Model for storage PVC data."""

    id: int = Field(..., description="PVC ID")
    created_at: datetime = Field(..., description="Creation timestamp")
    created_by: str = Field(..., description="Username of the creator")
    status: str = Field("Pending", description="PVC status")
    last_updated: datetime = Field(..., description="Last updated timestamp")

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "StoragePVC":
        """Create a StoragePVC instance from a database row.

        Args:
            row: Database row as dictionary

        Returns:
            StoragePVC: StoragePVC instance
        """
        return cls(
            id=row["id"],
            name=row["name"],
            namespace=row["namespace"],
            size=row["size"],
            is_public=row["is_public"],
            created_at=row["created_at"],
            created_by=row["created_by"],
            status=row["status"],
            last_updated=row["last_updated"],
        )

    @classmethod
    def list_from_rows(cls, rows: List[Dict[str, Any]]) -> List["StoragePVC"]:
        """Create a list of StoragePVC instances from database rows.

        Args:
            rows: List of database rows as dictionaries

        Returns:
            List[StoragePVC]: List of StoragePVC instances
        """
        return [cls.from_row(row) for row in rows]


class ConnectionPVCMap(APIModel):
    """Model for mapping connections to PVCs."""

    id: int = Field(..., description="Mapping ID")
    connection_id: int = Field(..., description="Connection ID")
    pvc_id: int = Field(..., description="PVC ID")
    created_at: datetime = Field(..., description="Creation timestamp")

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "ConnectionPVCMap":
        """Create a ConnectionPVCMap instance from a database row.

        Args:
            row: Database row as dictionary

        Returns:
            ConnectionPVCMap: ConnectionPVCMap instance
        """
        return cls(
            id=row["id"],
            connection_id=row["connection_id"],
            pvc_id=row["pvc_id"],
            created_at=row["created_at"],
        )

    @classmethod
    def list_from_rows(cls, rows: List[Dict[str, Any]]) -> List["ConnectionPVCMap"]:
        """Create a list of ConnectionPVCMap instances from database rows.

        Args:
            rows: List of database rows as dictionaries

        Returns:
            List[ConnectionPVCMap]: List of ConnectionPVCMap instances
        """
        return [cls.from_row(row) for row in rows]


class StoragePVCAccess(APIModel):
    """Model for storage PVC access control."""

    id: int = Field(..., description="Access ID")
    pvc_id: int = Field(..., description="PVC ID")
    username: str = Field(..., description="Username with access")
    created_at: datetime = Field(..., description="Creation timestamp")

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "StoragePVCAccess":
        """Create a StoragePVCAccess instance from a database row.

        Args:
            row: Database row as dictionary

        Returns:
            StoragePVCAccess: StoragePVCAccess instance
        """
        return cls(
            id=row["id"],
            pvc_id=row["pvc_id"],
            username=row["username"],
            created_at=row["created_at"],
        )

    @classmethod
    def list_from_rows(cls, rows: List[Dict[str, Any]]) -> List["StoragePVCAccess"]:
        """Create a list of StoragePVCAccess instances from database rows.

        Args:
            rows: List of database rows as dictionaries

        Returns:
            List[StoragePVCAccess]: List of StoragePVCAccess instances
        """
        return [cls.from_row(row) for row in rows]
