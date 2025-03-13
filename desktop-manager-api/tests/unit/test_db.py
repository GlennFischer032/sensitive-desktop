"""Test database setup and connection."""

import pytest
from desktop_manager.api.models.connection import Connection
from desktop_manager.api.models.user import User
from sqlalchemy.sql import text

from tests.config import TEST_USER


def test_database_connection(test_db):
    """Test that we can connect to the test database."""
    result = test_db.execute(text("SELECT 1")).scalar()
    assert result == 1


def test_create_tables(test_db):
    """Test that all tables are created correctly."""
    try:
        # Create a test user
        user = User(
            username=TEST_USER["username"],
            email=TEST_USER["email"],
            organization=TEST_USER["organization"],
        )
        test_db.add(user)
        test_db.commit()

        # Verify user was created
        created_user = (
            test_db.query(User).filter_by(username=TEST_USER["username"]).first()
        )
        assert created_user is not None
        assert created_user.email == TEST_USER["email"]

        # Test foreign key relationship
        connection = Connection(
            name="test_connection",
            created_by=user.username,
            guacamole_connection_id="test_guac_1",
        )
        test_db.add(connection)
        test_db.commit()

        # Verify connection was created with correct relationship
        created_connection = (
            test_db.query(Connection).filter_by(name="test_connection").first()
        )
        assert created_connection is not None
        assert created_connection.created_by == user.username
    except Exception as e:
        test_db.rollback()
        raise e


def test_foreign_key_constraint(test_db):
    """Test that foreign key constraints are working."""
    # Try to create a connection without a valid user
    connection = Connection(
        name="invalid_connection",
        created_by="non_existent_user",
        guacamole_connection_id="test_guac_2",
    )
    test_db.add(connection)

    # Should raise an integrity error
    with pytest.raises(Exception) as exc_info:
        test_db.commit()
    test_db.rollback()

    # The exact exception type might vary between SQLite and MySQL,
    # but there should be some kind of integrity error
    assert any(
        word in str(exc_info.value).lower()
        for word in ["foreign", "integrity", "constraint"]
    )
