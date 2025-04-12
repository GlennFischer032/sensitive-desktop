"""Connection repository module.

This module provides a repository for connection operations.
"""

from typing import Any

from sqlalchemy import and_
from sqlalchemy.orm import Session

from desktop_manager.database.models.connection import Connection
from desktop_manager.database.models.storage_pvc import ConnectionPVCMap, StoragePVC
from desktop_manager.database.repositories.base import BaseRepository


class ConnectionRepository(BaseRepository[Connection]):
    """Repository for connection operations.

    This class provides methods for connection-specific operations such as creating,
    updating, and retrieving connections, as well as managing connection-PVC mappings.
    """

    def __init__(self, session: Session):
        """Initialize the repository with a session.

        Args:
            session: SQLAlchemy session for database operations
        """
        super().__init__(session, Connection)

    def get_by_name(self, name: str) -> Connection | None:
        """Get a connection by its name.

        Args:
            name: Connection name

        Returns:
            Connection if found, None otherwise
        """
        return self.session.query(Connection).filter(Connection.name == name).first()

    def get_connections_by_creator(self, creator: str) -> list[Connection]:
        """Get connections by creator.

        Args:
            creator: Creator username

        Returns:
            List of connections created by the creator
        """
        return (
            self.session.query(Connection)
            .filter(Connection.created_by == creator)
            .order_by(Connection.created_at.desc())
            .all()
        )

    def get_by_id(self, connection_id: int) -> Connection | None:
        """Get a connection by its ID.

        Args:
            connection_id: Connection ID

        Returns:
            Connection if found, None otherwise
        """
        return self.session.query(Connection).filter(Connection.id == connection_id).first()

    def create_connection(self, data: dict[str, Any]) -> Connection:
        """Create a new connection.

        Args:
            data: Connection data including name, guacamole_connection_id, created_by, etc.

        Returns:
            Newly created connection
        """
        connection = Connection(
            name=data["name"],
            guacamole_connection_id=data["guacamole_connection_id"],
            created_by=data["created_by"],
            is_stopped=data.get("is_stopped", False),
            persistent_home=data.get("persistent_home", True),
            desktop_configuration_id=data.get("desktop_configuration_id"),
        )
        return self.create(connection)

    def update_connection(self, connection_id: int, data: dict[str, Any]) -> Connection | None:
        """Update a connection.

        Args:
            connection_id: Connection ID
            data: Updated connection data

        Returns:
            Updated connection if found, None otherwise
        """
        connection = self.get_by_id(connection_id)
        if connection:
            if "is_stopped" in data:
                connection.is_stopped = data["is_stopped"]
            if "guacamole_connection_id" in data:
                connection.guacamole_connection_id = data["guacamole_connection_id"]
            if "persistent_home" in data:
                connection.persistent_home = data["persistent_home"]
            if "desktop_configuration_id" in data:
                connection.desktop_configuration_id = data["desktop_configuration_id"]
            self.update(connection)
        return connection

    def delete_connection(self, connection_id: int) -> bool:
        """Delete a connection.

        Args:
            connection_id: Connection ID

        Returns:
            True if connection was deleted, False otherwise
        """
        connection = self.get_by_id(connection_id)
        if connection:
            self.session.delete(connection)
            self.session.commit()
            return True
        return False

    def get_connections_for_user(self, username: str) -> list[Connection]:
        """Get connections for a specific user.

        Args:
            username: Username

        Returns:
            List of connections created by the user
        """
        return (
            self.session.query(Connection)
            .filter(Connection.created_by == username)
            .order_by(Connection.created_at.desc())
            .all()
        )

    def get_all_connections(self) -> list[Connection]:
        """Get all connections.

        Returns:
            List of all connections
        """
        return self.session.query(Connection).order_by(Connection.created_at.desc()).all()

    # Connection-PVC mapping methods
    def map_connection_to_pvc(self, connection_id: int, pvc_id: int) -> ConnectionPVCMap:
        """Map a connection to a PVC.

        Args:
            connection_id: Connection ID
            pvc_id: PVC ID

        Returns:
            Created mapping
        """
        mapping = ConnectionPVCMap(connection_id=connection_id, pvc_id=pvc_id)
        self.session.add(mapping)
        self.session.commit()
        return mapping

    def unmap_connection_pvc(self, mapping_id: int) -> bool:
        """Remove a connection-PVC mapping.

        Args:
            mapping_id: Mapping ID

        Returns:
            True if mapping was removed, False otherwise
        """
        mapping = self.session.query(ConnectionPVCMap).filter(ConnectionPVCMap.id == mapping_id).first()
        if mapping:
            self.session.delete(mapping)
            self.session.commit()
            return True
        return False

    def get_connection_pvcs(self, connection_id: int) -> list[dict[str, Any]]:
        """Get PVCs associated with a connection.

        Args:
            connection_id: Connection ID

        Returns:
            List of PVCs with mapping information
        """
        pvcs = []
        connection = self.get_by_id(connection_id)
        if not connection:
            return pvcs

        # Using a join to get both PVC and mapping data
        result = (
            self.session.query(StoragePVC, ConnectionPVCMap)
            .join(
                ConnectionPVCMap,
                and_(
                    ConnectionPVCMap.pvc_id == StoragePVC.id,
                    ConnectionPVCMap.connection_id == connection_id,
                ),
            )
            .all()
        )

        for pvc, mapping in result:
            pvc_dict = {
                "id": pvc.id,
                "name": pvc.name,
                "namespace": pvc.namespace,
                "size": pvc.size,
                "is_public": pvc.is_public,
                "created_at": pvc.created_at,
                "created_by": pvc.created_by,
                "status": pvc.status,
                "last_updated": pvc.last_updated,
                "mapping_id": mapping.id,
                "connection_name": connection.name,
            }
            pvcs.append(pvc_dict)

        return pvcs

    def get_connections_for_pvc(self, pvc_id: int) -> list[Connection]:
        """Get connections that use a specific PVC.

        Args:
            pvc_id: PVC ID

        Returns:
            List of connections with mapping information
        """
        result = self.session.query(Connection).filter(Connection.pvcs.any(StoragePVC.id == pvc_id)).all()
        return result

    def is_pvc_attached_to_connection(self, connection_id: int, pvc_id: int) -> bool:
        """Check if a PVC is attached to a specific connection.

        Args:
            connection_id: Connection ID
            pvc_id: PVC ID

        Returns:
            True if PVC is attached to the connection, False otherwise
        """
        count = (
            self.session.query(ConnectionPVCMap)
            .filter(
                ConnectionPVCMap.connection_id == connection_id,
                ConnectionPVCMap.pvc_id == pvc_id,
            )
            .count()
        )
        return count > 0

    def is_pvc_in_use(self, pvc_id: int) -> bool:
        """Check if a PVC is in use by any connection.

        Args:
            pvc_id: PVC ID

        Returns:
            True if PVC is in use, False otherwise
        """
        count = self.session.query(ConnectionPVCMap).filter(ConnectionPVCMap.pvc_id == pvc_id).count()
        return count > 0
