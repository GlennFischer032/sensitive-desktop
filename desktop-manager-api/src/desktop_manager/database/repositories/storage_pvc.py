"""Storage PVC repository module.

This module provides a repository for storage PVC operations.
"""

from typing import Any

from sqlalchemy import or_
from sqlalchemy.orm import Session

from desktop_manager.database.models.storage_pvc import ConnectionPVCMap, StoragePVC, StoragePVCAccess
from desktop_manager.database.repositories.base import BaseRepository


class StoragePVCRepository(BaseRepository[StoragePVC]):
    """Repository for storage PVC operations.

    This class provides methods for PVC-specific operations such as creating,
    updating, and retrieving PVCs.
    """

    def __init__(self, session: Session):
        """Initialize the repository with a session.

        Args:
            session: SQLAlchemy session for database operations
        """
        super().__init__(session, StoragePVC)

    def get_by_name(self, name: str) -> StoragePVC | None:
        """Get a PVC by its name.

        Args:
            name: PVC name

        Returns:
            StoragePVC if found, None otherwise
        """
        return self.session.query(StoragePVC).filter(StoragePVC.name == name).first()

    def get_by_id(self, pvc_id: int) -> StoragePVC | None:
        """Get a PVC by its ID.

        Args:
            pvc_id: PVC ID

        Returns:
            StoragePVC if found, None otherwise
        """
        return self.session.query(StoragePVC).filter(StoragePVC.id == pvc_id).first()

    def create_storage_pvc(self, data: dict[str, Any]) -> StoragePVC:
        """Create a new storage PVC.

        Args:
            data: PVC data

        Returns:
            Newly created PVC
        """
        pvc = StoragePVC(
            name=data["name"],
            namespace=data["namespace"],
            size=data["size"],
            created_by=data["created_by"],
            status=data.get("status", "Pending"),
            is_public=data.get("is_public", False),
        )
        return self.create(pvc)

    def update_storage_pvc(self, pvc_id: int, data: dict[str, Any]) -> StoragePVC | None:
        """Update a storage PVC.

        Args:
            pvc_id: PVC ID
            data: Updated PVC data

        Returns:
            Updated PVC if found, None otherwise
        """
        pvc = self.get_by_id(pvc_id)
        if pvc:
            if "status" in data:
                pvc.status = data["status"]
            if "is_public" in data:
                pvc.is_public = data["is_public"]
            # Update automatically sets last_updated due to onupdate=func.now()
            self.update(pvc)
        return pvc

    def delete_storage_pvc(self, pvc_id: int) -> bool:
        """Delete a storage PVC.

        Args:
            pvc_id: PVC ID

        Returns:
            True if PVC was deleted, False otherwise
        """
        pvc = self.get_by_id(pvc_id)
        if pvc:
            self.session.delete(pvc)
            self.session.commit()
            return True
        return False

    def get_pvcs_for_admin(self) -> list[StoragePVC]:
        """Get all PVCs for admin users.

        Returns:
            List of all PVCs
        """
        return self.session.query(StoragePVC).order_by(StoragePVC.name).all()

    def get_pvcs_for_user(self, username: str) -> list[StoragePVC]:
        """Get PVCs for a specific user.

        This includes:
        - PVCs created by the user
        - Public PVCs
        - PVCs with explicit access for the user

        Args:
            username: Username

        Returns:
            List of accessible PVCs
        """
        return (
            self.session.query(StoragePVC)
            .filter(
                or_(
                    StoragePVC.is_public is True,
                    StoragePVC.id.in_(
                        self.session.query(StoragePVCAccess.pvc_id).filter(StoragePVCAccess.username == username)
                    ),
                )
            )
            .order_by(StoragePVC.name)
            .all()
        )

    # PVC Access methods
    def create_pvc_access(self, pvc_id: int, username: str) -> StoragePVCAccess:
        """Grant PVC access to a user.

        Args:
            pvc_id: PVC ID
            username: Username to grant access to

        Returns:
            Created access entry
        """
        access = StoragePVCAccess(pvc_id=pvc_id, username=username)
        self.session.add(access)
        self.session.commit()
        return access

    def clear_pvc_access(self, pvc_id: int) -> None:
        """Clear all access entries for a PVC.

        Args:
            pvc_id: PVC ID
        """
        self.session.query(StoragePVCAccess).filter(StoragePVCAccess.pvc_id == pvc_id).delete()
        self.session.commit()

    def get_pvc_access(self, pvc_id: int) -> list[StoragePVCAccess]:
        """Get all access entries for a PVC.

        Args:
            pvc_id: PVC ID

        Returns:
            List of access entries
        """
        return self.session.query(StoragePVCAccess).filter(StoragePVCAccess.pvc_id == pvc_id).all()

    def get_pvc_users(self, pvc_id: int) -> list[str]:
        """Get usernames with access to a PVC.

        Args:
            pvc_id: PVC ID

        Returns:
            List of usernames with access
        """
        access_entries = self.get_pvc_access(pvc_id)
        return [access.username for access in access_entries]

    def is_pvc_in_use(self, pvc_id: int) -> bool:
        """Check if a PVC is in use by any connection.

        Args:
            pvc_id: PVC ID

        Returns:
            True if PVC is in use, False otherwise
        """
        count = self.session.query(ConnectionPVCMap).filter(ConnectionPVCMap.pvc_id == pvc_id).count()
        return count > 0
