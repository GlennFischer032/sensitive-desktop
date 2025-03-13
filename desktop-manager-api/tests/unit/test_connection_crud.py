"""Unit tests for connection CRUD operations."""

import pytest
from desktop_manager.api.crud.connection import (
    create_connection,
    delete_connection,
    delete_user_connections,
    get_connection,
    get_connection_by_name,
    get_connections,
    get_user_connections,
    update_connection,
)
from desktop_manager.api.crud.user import create_user
from desktop_manager.api.schemas.connection import ConnectionCreate, ConnectionUpdate
from desktop_manager.api.schemas.user import UserCreate
from desktop_manager.core.exceptions import DatabaseError
from sqlalchemy.orm import Session

from tests.config import TEST_CONNECTION, TEST_USER


def test_crud_get_connection(test_db: Session):
    """Test getting a connection by ID."""
    # Create a user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        password=TEST_USER["password"],
        organization=TEST_USER["organization"],
    )
    user = create_user(test_db, user_data)

    # Create a connection
    connection_data = ConnectionCreate(
        name=TEST_CONNECTION["name"],
        guacamole_connection_id=TEST_CONNECTION["guacamole_connection_id"],
    )
    connection = create_connection(test_db, connection_data, user.username)

    # Get the connection by ID
    retrieved_connection = get_connection(test_db, connection.id)
    assert retrieved_connection is not None
    assert retrieved_connection.id == connection.id
    assert retrieved_connection.name == connection.name
    assert retrieved_connection.created_by == user.username


def test_crud_get_connection_by_name(test_db: Session):
    """Test getting a connection by name."""
    # Create a user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        password=TEST_USER["password"],
        organization=TEST_USER["organization"],
    )
    user = create_user(test_db, user_data)

    # Create a connection
    connection_data = ConnectionCreate(
        name=TEST_CONNECTION["name"],
        guacamole_connection_id=TEST_CONNECTION["guacamole_connection_id"],
    )
    connection = create_connection(test_db, connection_data, user.username)

    # Get the connection by name
    retrieved_connection = get_connection_by_name(test_db, connection.name)
    assert retrieved_connection is not None
    assert retrieved_connection.id == connection.id
    assert retrieved_connection.name == connection.name
    assert retrieved_connection.created_by == user.username


def test_crud_get_user_connections(test_db: Session):
    """Test getting all connections for a user."""
    # Create a user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        password=TEST_USER["password"],
        organization=TEST_USER["organization"],
    )
    user = create_user(test_db, user_data)

    # Create multiple connections
    connection_names = ["test_conn_1", "test_conn_2"]
    for name in connection_names:
        connection_data = ConnectionCreate(
            name=name, guacamole_connection_id=f"guac_{name}"
        )
        create_connection(test_db, connection_data, user.username)

    # Get user's connections
    connections = get_user_connections(test_db, user.username)
    assert len(connections) == 2
    assert all(conn.created_by == user.username for conn in connections)
    assert all(conn.name in connection_names for conn in connections)


def test_crud_get_connections(test_db: Session):
    """Test getting all connections with pagination."""
    # Create a user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        password=TEST_USER["password"],
        organization=TEST_USER["organization"],
    )
    user = create_user(test_db, user_data)

    # Create multiple connections
    connection_names = ["test_conn_1", "test_conn_2", "test_conn_3"]
    for name in connection_names:
        connection_data = ConnectionCreate(
            name=name, guacamole_connection_id=f"guac_{name}"
        )
        create_connection(test_db, connection_data, user.username)

    # Test pagination
    connections = get_connections(test_db, skip=1, limit=2)
    assert len(connections) == 2

    # Get all connections
    all_connections = get_connections(test_db)
    assert len(all_connections) == 3


def test_crud_create_connection(test_db: Session):
    """Test connection creation."""
    # Create a user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        password=TEST_USER["password"],
        organization=TEST_USER["organization"],
    )
    user = create_user(test_db, user_data)

    # Create a connection
    connection_data = ConnectionCreate(
        name=TEST_CONNECTION["name"],
        guacamole_connection_id=TEST_CONNECTION["guacamole_connection_id"],
    )
    connection = create_connection(test_db, connection_data, user.username)

    assert connection.id is not None
    assert connection.name == TEST_CONNECTION["name"]
    assert connection.created_by == user.username
    assert (
        connection.guacamole_connection_id == TEST_CONNECTION["guacamole_connection_id"]
    )
    assert connection.created_at is not None


def test_crud_create_duplicate_connection(test_db: Session):
    """Test that creating a connection with duplicate name fails."""
    # Create a user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        password=TEST_USER["password"],
        organization=TEST_USER["organization"],
    )
    user = create_user(test_db, user_data)

    # Create first connection
    connection_data = ConnectionCreate(
        name=TEST_CONNECTION["name"],
        guacamole_connection_id=TEST_CONNECTION["guacamole_connection_id"],
    )
    create_connection(test_db, connection_data, user.username)

    # Try to create second connection with same name
    with pytest.raises(
        DatabaseError,
        match=f"Connection with name '{TEST_CONNECTION['name']}' already exists",
    ):
        create_connection(test_db, connection_data, user.username)


def test_crud_update_connection(test_db: Session):
    """Test connection update."""
    # Create a user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        password=TEST_USER["password"],
        organization=TEST_USER["organization"],
    )
    user = create_user(test_db, user_data)

    # Create a connection
    connection_data = ConnectionCreate(
        name=TEST_CONNECTION["name"],
        guacamole_connection_id=TEST_CONNECTION["guacamole_connection_id"],
    )
    connection = create_connection(test_db, connection_data, user.username)

    # Update the connection
    new_name = "updated_connection"
    new_guac_id = "updated_guac_id"
    update_data = ConnectionUpdate(name=new_name, guacamole_connection_id=new_guac_id)
    updated_connection = update_connection(test_db, connection.id, update_data)

    assert updated_connection is not None
    assert updated_connection.name == new_name
    assert updated_connection.guacamole_connection_id == new_guac_id
    assert updated_connection.created_by == user.username


def test_crud_update_nonexistent_connection(test_db: Session):
    """Test updating a nonexistent connection."""
    update_data = ConnectionUpdate(name="new_name")
    updated_connection = update_connection(test_db, 999, update_data)
    assert updated_connection is None


def test_crud_update_connection_duplicate_name(test_db: Session):
    """Test that updating a connection to a duplicate name fails."""
    # Create a user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        password=TEST_USER["password"],
        organization=TEST_USER["organization"],
    )
    user = create_user(test_db, user_data)

    # Create two connections
    connection1_data = ConnectionCreate(
        name="connection1", guacamole_connection_id="guac1"
    )
    connection1 = create_connection(test_db, connection1_data, user.username)

    connection2_data = ConnectionCreate(
        name="connection2", guacamole_connection_id="guac2"
    )
    create_connection(test_db, connection2_data, user.username)

    # Try to update connection1 to have the same name as connection2
    update_data = ConnectionUpdate(name="connection2")
    with pytest.raises(
        DatabaseError, match="Connection with name 'connection2' already exists"
    ):
        update_connection(test_db, connection1.id, update_data)


def test_crud_delete_connection(test_db: Session):
    """Test connection deletion."""
    # Create a user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        password=TEST_USER["password"],
        organization=TEST_USER["organization"],
    )
    user = create_user(test_db, user_data)

    # Create a connection
    connection_data = ConnectionCreate(
        name=TEST_CONNECTION["name"],
        guacamole_connection_id=TEST_CONNECTION["guacamole_connection_id"],
    )
    connection = create_connection(test_db, connection_data, user.username)

    # Delete the connection
    success = delete_connection(test_db, connection.id)
    assert success

    # Verify connection is deleted
    deleted_connection = get_connection(test_db, connection.id)
    assert deleted_connection is None


def test_crud_delete_nonexistent_connection(test_db: Session):
    """Test deleting a nonexistent connection."""
    success = delete_connection(test_db, 999)
    assert not success


def test_crud_delete_user_connections(test_db: Session):
    """Test deleting all connections for a user."""
    # Create a user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        password=TEST_USER["password"],
        organization=TEST_USER["organization"],
    )
    user = create_user(test_db, user_data)

    # Create multiple connections
    connection_names = ["test_conn_1", "test_conn_2", "test_conn_3"]
    for name in connection_names:
        connection_data = ConnectionCreate(
            name=name, guacamole_connection_id=f"guac_{name}"
        )
        create_connection(test_db, connection_data, user.username)

    # Delete all user's connections
    deleted_count = delete_user_connections(test_db, user.username)
    assert deleted_count == 3

    # Verify all connections are deleted
    remaining_connections = get_user_connections(test_db, user.username)
    assert len(remaining_connections) == 0
