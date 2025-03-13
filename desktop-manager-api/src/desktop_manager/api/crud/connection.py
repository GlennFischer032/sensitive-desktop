"""CRUD operations for connections."""

import logging
from typing import List, Optional

from desktop_manager.api.models.connection import Connection
from desktop_manager.api.schemas.connection import ConnectionCreate, ConnectionUpdate
from desktop_manager.core.exceptions import DatabaseError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session


logger = logging.getLogger(__name__)


def get_connection(db: Session, connection_id: int) -> Optional[Connection]:
    """Get a connection by ID.

    Args:
        db: Database session
        connection_id: ID of the connection to retrieve

    Returns:
        Connection if found, None otherwise
    """
    return db.query(Connection).filter(Connection.id == connection_id).first()


def get_connection_by_name(db: Session, name: str) -> Optional[Connection]:
    """Get a connection by name.

    Args:
        db: Database session
        name: Name of the connection to retrieve

    Returns:
        Connection if found, None otherwise
    """
    return db.query(Connection).filter(Connection.name == name).first()


def get_user_connections(
    db: Session, username: str, skip: int = 0, limit: int = 100
) -> List[Connection]:
    """Get all connections created by a specific user.

    Args:
        db: Database session
        username: Username of the connection creator
        skip: Number of records to skip (for pagination)
        limit: Maximum number of records to return

    Returns:
        List of connections
    """
    return (
        db.query(Connection)
        .filter(Connection.created_by == username)
        .offset(skip)
        .limit(limit)
        .all()
    )


def get_connections(db: Session, skip: int = 0, limit: int = 100) -> List[Connection]:
    """Get all connections with pagination.

    Args:
        db: Database session
        skip: Number of records to skip (for pagination)
        limit: Maximum number of records to return

    Returns:
        List of connections
    """
    return db.query(Connection).offset(skip).limit(limit).all()


def create_connection(db: Session, connection: ConnectionCreate, username: str) -> Connection:
    """Create a new connection.

    Args:
        db: Database session
        connection: Connection data
        username: Username of the creator

    Returns:
        Created connection

    Raises:
        DatabaseError: If connection creation fails
    """
    try:
        db_connection = Connection(
            name=connection.name,
            created_by=username,
            guacamole_connection_id=connection.guacamole_connection_id,
        )
        db.add(db_connection)
        db.commit()
        db.refresh(db_connection)
        return db_connection
    except IntegrityError as e:
        db.rollback()
        logger.error("Failed to create connection: %s", str(e))
        if "UNIQUE constraint failed: connections.name" in str(e):
            raise DatabaseError(f"Connection with name '{connection.name}' already exists") from e
        raise DatabaseError(f"Failed to create connection: {e!s}") from e
    except Exception as e:
        db.rollback()
        logger.error("Unexpected error creating connection: %s", str(e))
        raise DatabaseError(f"Failed to create connection: {e!s}") from e


def update_connection(
    db: Session, connection_id: int, connection_update: ConnectionUpdate
) -> Optional[Connection]:
    """Update a connection.

    Args:
        db: Database session
        connection_id: ID of the connection to update
        connection_update: Updated connection data

    Returns:
        Updated connection if found and updated, None otherwise

    Raises:
        DatabaseError: If connection update fails
    """
    try:
        db_connection = get_connection(db, connection_id)
        if not db_connection:
            return None

        # Update only provided fields
        update_data = connection_update.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(db_connection, field, value)

        db.commit()
        db.refresh(db_connection)
        return db_connection
    except IntegrityError as e:
        db.rollback()
        logger.error("Failed to update connection: %s", str(e))
        if "UNIQUE constraint failed: connections.name" in str(e):
            raise DatabaseError(
                f"Connection with name '{connection_update.name}' already exists"
            ) from e
        raise DatabaseError(f"Failed to update connection: {e!s}") from e
    except Exception as e:
        db.rollback()
        logger.error("Unexpected error updating connection: %s", str(e))
        raise DatabaseError(f"Failed to update connection: {e!s}") from e


def delete_connection(db: Session, connection_id: int) -> bool:
    """Delete a connection.

    Args:
        db: Database session
        connection_id: ID of the connection to delete

    Returns:
        True if connection was deleted, False if not found

    Raises:
        DatabaseError: If connection deletion fails
    """
    try:
        db_connection = get_connection(db, connection_id)
        if not db_connection:
            return False

        db.delete(db_connection)
        db.commit()
        return True
    except Exception as e:
        db.rollback()
        logger.error("Failed to delete connection: %s", str(e))
        raise DatabaseError(f"Failed to delete connection: {e!s}") from e


def delete_user_connections(db: Session, username: str) -> int:
    """Delete all connections for a user.

    Args:
        db: Database session
        username: Username whose connections to delete

    Returns:
        Number of connections deleted

    Raises:
        DatabaseError: If connection deletion fails
    """
    try:
        result = db.query(Connection).filter(Connection.created_by == username).delete()
        db.commit()
        return result
    except Exception as e:
        db.rollback()
        logger.error("Failed to delete user connections: %s", str(e))
        raise DatabaseError(f"Failed to delete user connections: {e!s}") from e
