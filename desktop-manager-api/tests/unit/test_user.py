"""Unit tests for user operations."""

import pytest
from desktop_manager.api.crud.user import (
    create_user,
    delete_user,
    get_user,
    get_user_by_username,
    get_users,
)
from desktop_manager.api.models.user import User
from desktop_manager.api.schemas.user import UserCreate
from desktop_manager.api.services.user_service import UserService
from desktop_manager.core.exceptions import GuacamoleError
from sqlalchemy.orm import Session

from tests.config import TEST_ADMIN, TEST_USER


def test_create_user(test_db: Session):
    """Test user creation."""
    # Create a test user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        password=TEST_USER["password"],
        organization=TEST_USER["organization"],
    )

    user = create_user(test_db, user_data)
    assert user is not None
    assert user.username == TEST_USER["username"]
    assert user.email == TEST_USER["email"]
    assert user.organization == TEST_USER["organization"]
    assert user.password_hash is not None
    assert user.password_hash != TEST_USER["password"]  # Password should be hashed
    assert not user.is_admin


def test_create_admin_user(test_db: Session):
    """Test admin user creation."""
    admin_data = UserCreate(
        username=TEST_ADMIN["username"],
        email=TEST_ADMIN["email"],
        password=TEST_ADMIN["password"],
        organization=TEST_ADMIN["organization"],
        is_admin=True,
    )

    admin = create_user(test_db, admin_data)
    assert admin is not None
    assert admin.username == TEST_ADMIN["username"]
    assert admin.is_admin


def test_get_user(test_db: Session):
    """Test retrieving a user by ID."""
    # First create a user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        password=TEST_USER["password"],
        organization=TEST_USER["organization"],
    )
    created_user = create_user(test_db, user_data)

    # Then retrieve it
    user = get_user(test_db, created_user.id)
    assert user is not None
    assert user.id == created_user.id
    assert user.username == TEST_USER["username"]


def test_get_user_by_username(test_db: Session):
    """Test retrieving a user by username."""
    # First create a user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        password=TEST_USER["password"],
        organization=TEST_USER["organization"],
    )
    create_user(test_db, user_data)

    # Then retrieve it by username
    user = get_user_by_username(test_db, TEST_USER["username"])
    assert user is not None
    assert user.username == TEST_USER["username"]
    assert user.email == TEST_USER["email"]


def test_get_users(test_db: Session):
    """Test retrieving multiple users."""
    # Create test users
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        password=TEST_USER["password"],
        organization=TEST_USER["organization"],
    )
    admin_data = UserCreate(
        username=TEST_ADMIN["username"],
        email=TEST_ADMIN["email"],
        password=TEST_ADMIN["password"],
        organization=TEST_ADMIN["organization"],
        is_admin=True,
    )

    create_user(test_db, user_data)
    create_user(test_db, admin_data)

    # Retrieve all users
    users = get_users(test_db)
    assert len(users) == 2
    assert any(u.username == TEST_USER["username"] for u in users)
    assert any(u.username == TEST_ADMIN["username"] for u in users)


def test_create_duplicate_user(test_db: Session):
    """Test that creating a user with duplicate username fails."""
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        password=TEST_USER["password"],
        organization=TEST_USER["organization"],
    )

    # Create first user
    create_user(test_db, user_data)

    # Attempt to create duplicate user
    with pytest.raises(ValueError, match="Username already exists"):
        create_user(test_db, user_data)


def test_delete_user(test_db: Session):
    """Test user deletion."""
    # First create a user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        password=TEST_USER["password"],
        organization=TEST_USER["organization"],
    )
    created_user = create_user(test_db, user_data)

    # Delete the user
    success = delete_user(test_db, created_user.id)
    assert success

    # Verify user is deleted
    deleted_user = get_user(test_db, created_user.id)
    assert deleted_user is None


def test_delete_nonexistent_user(test_db: Session):
    """Test deleting a nonexistent user."""
    success = delete_user(test_db, 999)  # Non-existent ID
    assert not success


def test_delete_user_not_in_guacamole(test_db: Session, mock_guacamole_client, mocker):
    """Test deleting a user that exists in the database but not in Guacamole."""
    # Create a test user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        password=TEST_USER["password"],
        organization=TEST_USER["organization"],
    )
    create_user(test_db, user_data)

    # Mock the delete_guacamole_user function to raise GuacamoleError
    mock_delete = mocker.patch(
        "desktop_manager.api.services.user_service.delete_guacamole_user"
    )
    mock_delete.side_effect = GuacamoleError("User not found in Guacamole")

    # Configure mock Guacamole client
    mock_guacamole_client.login.return_value = "mock_token"

    # Create UserService with mock
    user_service = UserService(test_db, mock_guacamole_client)

    # Delete user - should succeed even though user is not in Guacamole
    user_service.delete_user(TEST_USER["username"])

    # Verify user is deleted from database
    test_db.expire_all()  # Expire all objects to ensure fresh data
    user = test_db.query(User).filter(User.username == TEST_USER["username"]).first()
    assert user is None

    # Verify mock was called correctly
    mock_delete.assert_called_once_with("mock_token", TEST_USER["username"])


def test_delete_user_guacamole_error(test_db: Session, mock_guacamole_client, mocker):
    """Test that network/other Guacamole errors prevent user deletion."""
    # Create a test user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        password=TEST_USER["password"],
        organization=TEST_USER["organization"],
    )
    create_user(test_db, user_data)

    # Mock the delete_guacamole_user function to raise GuacamoleError
    mock_delete = mocker.patch(
        "desktop_manager.api.services.user_service.delete_guacamole_user"
    )
    mock_delete.side_effect = GuacamoleError("Network error connecting to Guacamole")

    # Configure mock Guacamole client
    mock_guacamole_client.login.return_value = "mock_token"

    # Create UserService with mock
    user_service = UserService(test_db, mock_guacamole_client)

    # Attempt to delete user - should fail due to Guacamole error
    with pytest.raises(GuacamoleError, match="Network error connecting to Guacamole"):
        user_service.delete_user(TEST_USER["username"])

    # Verify user still exists in database
    test_db.expire_all()  # Expire all objects to ensure fresh data
    user = test_db.query(User).filter(User.username == TEST_USER["username"]).first()
    assert user is not None
    assert user.username == TEST_USER["username"]

    # Verify mock was called correctly
    mock_delete.assert_called_once_with("mock_token", TEST_USER["username"])
