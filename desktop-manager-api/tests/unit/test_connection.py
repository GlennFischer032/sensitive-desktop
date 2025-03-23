"""Unit tests for connection operations."""

import pytest
from desktop_manager.api.models.connection import Connection
from desktop_manager.api.models.user import User
from desktop_manager.api.schemas.user import UserCreate
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from werkzeug.security import generate_password_hash

from tests.config import TEST_CONNECTION, TEST_USER


def create_user_for_testing(test_db: Session, user_data: UserCreate) -> User:
    """Helper function to create a user for testing.

    Args:
        test_db: SQLAlchemy session
        user_data: User creation data

    Returns:
        The created user
    """
    # Create a user directly
    user = User(
        username=user_data.username,
        email=user_data.email,
        password_hash=generate_password_hash(user_data.password) if user_data.password else None,
        organization=user_data.organization,
    )
    test_db.add(user)
    test_db.commit()
    test_db.refresh(user)
    return user


def test_create_connection(test_db: Session):
    """Test connection creation."""
    # First create a user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        password=TEST_USER["password"],
        organization=TEST_USER["organization"],
    )
    user = create_user_for_testing(test_db, user_data)

    # Create a connection
    connection = Connection(
        name=TEST_CONNECTION["name"],
        created_by=user.username,
        guacamole_connection_id=TEST_CONNECTION["guacamole_connection_id"],
    )
    test_db.add(connection)
    test_db.commit()
    test_db.refresh(connection)

    # Verify connection was created
    assert connection.id is not None
    assert connection.name == TEST_CONNECTION["name"]
    assert connection.created_by == user.username
    assert (
        connection.guacamole_connection_id == TEST_CONNECTION["guacamole_connection_id"]
    )
    assert connection.created_at is not None


def test_connection_user_relationship(test_db: Session):
    """Test the relationship between connections and users."""
    # Create a user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        password=TEST_USER["password"],
        organization=TEST_USER["organization"],
    )
    user = create_user_for_testing(test_db, user_data)

    # Create multiple connections for the user
    connection_names = ["test_conn_1", "test_conn_2"]
    for i, name in enumerate(connection_names):
        connection = Connection(
            name=name,
            created_by=user.username,
            guacamole_connection_id=f"test_guac_{i}",
        )
        test_db.add(connection)
    test_db.commit()

    # Verify relationships
    user_connections = (
        test_db.query(Connection).filter(Connection.created_by == user.username).all()
    )
    assert len(user_connections) == 2
    assert all(conn.creator.username == user.username for conn in user_connections)
    assert len(user.connections) == 2
    assert all(conn.name in connection_names for conn in user.connections)


def test_create_duplicate_connection(test_db: Session):
    """Test that creating a connection with duplicate name fails."""
    # Create a user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        password=TEST_USER["password"],
        organization=TEST_USER["organization"],
    )
    user = create_user_for_testing(test_db, user_data)

    # Create first connection
    connection1 = Connection(
        name=TEST_CONNECTION["name"],
        created_by=user.username,
        guacamole_connection_id=TEST_CONNECTION["guacamole_connection_id"],
    )
    test_db.add(connection1)
    test_db.commit()

    # Try to create second connection with same name
    connection2 = Connection(
        name=TEST_CONNECTION["name"],  # Same name
        created_by=user.username,
        guacamole_connection_id="different_id",
    )
    test_db.add(connection2)

    # Should raise IntegrityError
    with pytest.raises(IntegrityError):
        test_db.commit()
    test_db.rollback()


def test_delete_connection(test_db: Session):
    """Test connection deletion."""
    # Create a user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        password=TEST_USER["password"],
        organization=TEST_USER["organization"],
    )
    user = create_user_for_testing(test_db, user_data)

    # Create a connection
    connection = Connection(
        name=TEST_CONNECTION["name"],
        created_by=user.username,
        guacamole_connection_id=TEST_CONNECTION["guacamole_connection_id"],
    )
    test_db.add(connection)
    test_db.commit()

    # Delete the connection
    test_db.delete(connection)
    test_db.commit()

    # Verify connection is deleted
    deleted_connection = (
        test_db.query(Connection)
        .filter(Connection.name == TEST_CONNECTION["name"])
        .first()
    )
    assert deleted_connection is None


def test_cascade_delete_user_connections(test_db: Session):
    """Test that deleting a user cascades to their connections."""
    # Create a user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        password=TEST_USER["password"],
        organization=TEST_USER["organization"],
    )
    user = create_user_for_testing(test_db, user_data)

    # Create connections for the user
    connection_names = ["test_conn_1", "test_conn_2"]
    for i, name in enumerate(connection_names):
        connection = Connection(
            name=name,
            created_by=user.username,
            guacamole_connection_id=f"test_guac_{i}",
        )
        test_db.add(connection)
    test_db.commit()

    # Delete the user
    test_db.delete(user)
    test_db.commit()

    # Verify all connections are deleted
    remaining_connections = (
        test_db.query(Connection).filter(Connection.created_by == user.username).all()
    )
    assert len(remaining_connections) == 0


def test_connection_without_user(test_db: Session):
    """Test that creating a connection without a valid user fails."""
    # Try to create a connection with non-existent user
    connection = Connection(
        name=TEST_CONNECTION["name"],
        created_by="nonexistent_user",
        guacamole_connection_id=TEST_CONNECTION["guacamole_connection_id"],
    )
    test_db.add(connection)

    # Should raise IntegrityError due to foreign key constraint
    with pytest.raises(IntegrityError):
        test_db.commit()
    test_db.rollback()
