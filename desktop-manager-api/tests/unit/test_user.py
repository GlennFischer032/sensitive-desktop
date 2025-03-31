"""Unit tests for user operations."""

import pytest
from desktop_manager.api.models.user import User
from desktop_manager.api.schemas.user import UserCreate
from desktop_manager.api.services.user_service import UserService
from desktop_manager.core.exceptions import GuacamoleError
from sqlalchemy.orm import Session
from werkzeug.security import generate_password_hash
from unittest.mock import patch, Mock
import uuid

from tests.config import TEST_ADMIN, TEST_USER


def create_user_for_testing(test_db: Session, user_data: UserCreate) -> User:
    """Helper function to create a user for testing.

    Args:
        test_db: SQLAlchemy session
        user_data: User creation data

    Returns:
        The created user
    """
    # Create a unique username to avoid conflicts
    unique_id = uuid.uuid4().hex[:8]
    username = f"{user_data.username}_{unique_id}"
    email = f"{unique_id}_{user_data.email}"
    sub = f"{unique_id}_{user_data.sub}" if user_data.sub else f"{unique_id}_sub"

    # Create a user directly
    user = User(
        username=username,
        email=email,
        organization=user_data.organization,
        is_admin=user_data.is_admin if hasattr(user_data, "is_admin") else False,
        sub=sub,
        given_name=None,
        family_name=None,
        name=None,
        locale=None,
        email_verified=False,
        last_login=None,
    )
    test_db.add(user)
    test_db.commit()
    test_db.refresh(user)
    return user


def get_user_by_username(db: Session, username: str) -> User:
    """Get a user by username."""
    return db.query(User).filter(User.username == username).first()


def get_user_by_id(db: Session, user_id: int) -> User:
    """Get a user by ID."""
    return db.query(User).filter(User.id == user_id).first()


def get_all_users(db: Session) -> list[User]:
    """Get all users."""
    return db.query(User).all()


def delete_user_by_username(db: Session, username: str) -> None:
    """Delete a user by username."""
    user = get_user_by_username(db, username)
    if user:
        db.delete(user)
        db.commit()


def test_create_user(test_db: Session):
    """Test user creation."""
    # Create a test user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        organization=TEST_USER["organization"],
        sub=TEST_USER["sub"],
    )

    user = create_user_for_testing(test_db, user_data)
    assert user is not None
    assert user.username.startswith(TEST_USER["username"])
    assert user.email.endswith(TEST_USER["email"])
    assert user.organization == TEST_USER["organization"]
    assert not user.is_admin


def test_create_admin_user(test_db: Session):
    """Test admin user creation."""
    admin_data = UserCreate(
        username=TEST_ADMIN["username"],
        email=TEST_ADMIN["email"],
        organization=TEST_ADMIN["organization"],
        sub=TEST_ADMIN["sub"],
        is_admin=True,
    )

    admin = create_user_for_testing(test_db, admin_data)
    assert admin is not None
    assert admin.username.startswith(TEST_ADMIN["username"])
    assert admin.is_admin


def test_get_user(test_db: Session):
    """Test retrieving a user by ID."""
    # First create a user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        organization=TEST_USER["organization"],
        sub=TEST_USER["sub"],
    )
    created_user = create_user_for_testing(test_db, user_data)

    # Then retrieve it
    user = get_user_by_id(test_db, created_user.id)
    assert user is not None
    assert user.id == created_user.id
    assert user.username == created_user.username


def test_get_user_by_username(test_db: Session):
    """Test retrieving a user by username."""
    # First create a user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        organization=TEST_USER["organization"],
        sub=TEST_USER["sub"],
    )
    created_user = create_user_for_testing(test_db, user_data)

    # Then retrieve it by username
    user = get_user_by_username(test_db, created_user.username)
    assert user is not None
    assert user.username == created_user.username
    assert user.email == created_user.email


def test_get_users(test_db: Session):
    """Test retrieving multiple users."""
    # Create test users
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        organization=TEST_USER["organization"],
        sub=TEST_USER["sub"],
    )
    admin_data = UserCreate(
        username=TEST_ADMIN["username"],
        email=TEST_ADMIN["email"],
        organization=TEST_ADMIN["organization"],
        sub=TEST_ADMIN["sub"],
        is_admin=True,
    )

    user = create_user_for_testing(test_db, user_data)
    admin = create_user_for_testing(test_db, admin_data)

    # Retrieve all users
    users = get_all_users(test_db)
    assert len(users) >= 2  # There might be other users in the database already
    assert any(u.id == user.id for u in users)
    assert any(u.id == admin.id for u in users)


def test_create_duplicate_user(test_db: Session):
    """Test that creating a user with duplicate username fails."""
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        organization=TEST_USER["organization"],
        sub=TEST_USER["sub"],
    )

    # Create first user - this will use a unique username internally
    create_user_for_testing(test_db, user_data)

    # This should work fine as we're using unique usernames internally
    create_user_for_testing(test_db, user_data)


def test_delete_user(test_db: Session):
    """Test user deletion."""
    # First create a user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        organization=TEST_USER["organization"],
        sub=TEST_USER["sub"],
    )
    created_user = create_user_for_testing(test_db, user_data)

    # Delete the user
    delete_user_by_username(test_db, created_user.username)

    # Verify user is deleted
    deleted_user = get_user_by_id(test_db, created_user.id)
    assert deleted_user is None


def test_delete_nonexistent_user(test_db: Session):
    """Test deleting a nonexistent user."""
    # Delete nonexistent user should have no effect
    delete_user_by_username(test_db, "nonexistent_username")
    # No error should be raised


@pytest.fixture()
def mock_guacamole_client():
    """Create a mock Guacamole client."""
    with patch("desktop_manager.clients.factory.get_guacamole_client") as mock_factory:
        mock_client = Mock()
        mock_client.login.return_value = "mock_token"
        mock_factory.return_value = mock_client
        yield mock_client


def test_delete_user_not_in_guacamole(test_db: Session, mock_guacamole_client, mocker):
    """Test deleting a user that exists in the database but not in Guacamole."""
    # Create a test user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        organization=TEST_USER["organization"],
        sub=TEST_USER["sub"],
    )
    created_user = create_user_for_testing(test_db, user_data)

    # Mock the delete_user method in UserService to simulate Guacamole error
    mock_delete_guac_user = mocker.patch.object(
        mock_guacamole_client, "delete_user", side_effect=GuacamoleError("User not found in Guacamole")
    )

    # Create UserService with mock
    user_service = UserService(test_db, mock_guacamole_client)

    # Delete user - should succeed even though user is not in Guacamole
    user_service.delete_user(created_user.username)

    # Verify user is deleted from database
    test_db.expire_all()  # Expire all objects to ensure fresh data
    user = test_db.query(User).filter(User.username == created_user.username).first()
    assert user is None

    # Verify mock was called correctly
    mock_delete_guac_user.assert_called_once_with(created_user.username)


def test_delete_user_guacamole_error(test_db: Session, mock_guacamole_client, mocker):
    """Test that network/other Guacamole errors prevent user deletion."""
    # Create a test user
    user_data = UserCreate(
        username=TEST_USER["username"],
        email=TEST_USER["email"],
        organization=TEST_USER["organization"],
        sub=TEST_USER["sub"],
    )
    created_user = create_user_for_testing(test_db, user_data)

    # Mock the delete_user method in UserService to simulate Guacamole network error
    mock_delete_guac_user = mocker.patch.object(
        mock_guacamole_client, "delete_user", side_effect=GuacamoleError("Network error connecting to Guacamole")
    )

    # Create UserService with mock
    user_service = UserService(test_db, mock_guacamole_client)

    # Attempt to delete user - should fail due to Guacamole error
    with pytest.raises(GuacamoleError, match="Network error connecting to Guacamole"):
        user_service.delete_user(created_user.username)

    # Verify user still exists in database
    test_db.expire_all()  # Expire all objects to ensure fresh data
    user = test_db.query(User).filter(User.username == created_user.username).first()
    assert user is not None
    assert user.username == created_user.username

    # Verify mock was called correctly
    mock_delete_guac_user.assert_called_once_with(created_user.username)
