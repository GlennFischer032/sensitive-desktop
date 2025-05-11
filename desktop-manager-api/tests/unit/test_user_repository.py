"""
Unit tests for the UserRepository class.
"""

import pytest
import sys
import os
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from database.repositories.user import UserRepository
from database.models.user import User, SocialAuthAssociation, PKCEState


class TestUserRepository:
    """Tests for the UserRepository class."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session for testing."""
        session = MagicMock()

        # Mock query builder
        query = MagicMock()
        session.query.return_value = query
        query.filter.return_value = query
        query.order_by.return_value = query

        return session

    @pytest.fixture
    def user_repo(self, mock_session):
        """Create a UserRepository instance with a mock session."""
        return UserRepository(mock_session)

    @pytest.fixture
    def sample_user(self):
        """Create a sample user for testing."""
        user = MagicMock(spec=User)
        user.id = 1
        user.username = "testuser"
        user.email = "test@example.com"
        user.is_admin = False
        user.sub = "subject123"
        user.given_name = "Test"
        user.family_name = "User"
        user.name = "Test User"
        user.organization = "Test Org"
        user.locale = "en-US"
        user.email_verified = True
        user.last_login = None
        return user

    @pytest.fixture
    def sample_social_auth(self):
        """Create a sample social auth association for testing."""
        social_auth = MagicMock(spec=SocialAuthAssociation)
        social_auth.id = 1
        social_auth.user_id = 1
        social_auth.provider = "github"
        social_auth.provider_user_id = "github123"
        social_auth.provider_name = "GitHub"
        social_auth.extra_data = {"avatar_url": "https://example.com/avatar.png"}
        social_auth.last_used = None
        return social_auth

    @pytest.fixture
    def sample_pkce_state(self):
        """Create a sample PKCE state for testing."""
        now = datetime.utcnow()
        pkce_state = MagicMock(spec=PKCEState)
        pkce_state.id = 1
        pkce_state.state = "random_state_string"
        pkce_state.code_verifier = "random_code_verifier"
        pkce_state.expires_at = now + timedelta(minutes=10)
        pkce_state.used = False
        return pkce_state

    def test_get_by_username(self, user_repo, mock_session, sample_user):
        """
        GIVEN a username
        WHEN get_by_username is called
        THEN it should return the user with that username
        """
        # Setup
        query = mock_session.query.return_value
        query.filter.return_value.first.return_value = sample_user

        # Execute
        result = user_repo.get_by_username("testuser")

        # Verify
        assert result == sample_user
        mock_session.query.assert_called_once_with(User)
        query.filter.assert_called_once()
        query.filter.return_value.first.assert_called_once()

    def test_get_by_sub(self, user_repo, mock_session, sample_user):
        """
        GIVEN an OIDC subject identifier
        WHEN get_by_sub is called
        THEN it should return the user with that subject
        """
        # Setup
        query = mock_session.query.return_value
        query.filter.return_value.first.return_value = sample_user

        # Execute
        result = user_repo.get_by_sub("subject123")

        # Verify
        assert result == sample_user
        mock_session.query.assert_called_once_with(User)
        query.filter.assert_called_once()
        query.filter.return_value.first.assert_called_once()

    def test_get_by_email(self, user_repo, mock_session, sample_user):
        """
        GIVEN an email address
        WHEN get_by_email is called
        THEN it should return the user with that email
        """
        # Setup
        query = mock_session.query.return_value
        query.filter.return_value.first.return_value = sample_user

        # Execute
        result = user_repo.get_by_email("test@example.com")

        # Verify
        assert result == sample_user
        mock_session.query.assert_called_once_with(User)
        query.filter.assert_called_once()
        query.filter.return_value.first.assert_called_once()

    def test_create_user(self, user_repo, mock_session):
        """
        GIVEN user data
        WHEN create_user is called
        THEN it should create and return a new user
        """
        # Setup - mock the BaseRepository.create method
        with patch.object(user_repo, "create", return_value=MagicMock(spec=User)) as mock_create:
            # User data for creating a new user
            user_data = {
                "username": "newuser",
                "email": "newuser@example.com",
                "is_admin": True,
                "sub": "newsub123",
                "given_name": "New",
                "family_name": "User",
                "name": "New User",
                "organization": "New Org",
                "locale": "fr-FR",
                "email_verified": True,
            }

            # Execute
            result = user_repo.create_user(user_data)

            # Verify
            assert result is not None
            mock_create.assert_called_once()

            # Check that User was created with correct parameters
            created_user = mock_create.call_args[0][0]
            assert created_user.username == "newuser"
            assert created_user.email == "newuser@example.com"
            assert created_user.is_admin is True
            assert created_user.sub == "newsub123"
            assert created_user.given_name == "New"
            assert created_user.family_name == "User"
            assert created_user.name == "New User"
            assert created_user.organization == "New Org"
            assert created_user.locale == "fr-FR"
            assert created_user.email_verified is True

    def test_create_user_minimal_data(self, user_repo, mock_session):
        """
        GIVEN minimal user data (just username)
        WHEN create_user is called
        THEN it should create a user with default values for optional fields
        """
        # Setup - mock the BaseRepository.create method
        with patch.object(user_repo, "create", return_value=MagicMock(spec=User)) as mock_create:
            # Minimal user data
            user_data = {
                "username": "minimaluser",
            }

            # Execute
            result = user_repo.create_user(user_data)

            # Verify
            assert result is not None
            mock_create.assert_called_once()

            # Check that User was created with correct parameters
            created_user = mock_create.call_args[0][0]
            assert created_user.username == "minimaluser"
            assert created_user.email is None
            assert created_user.is_admin is False  # Default value
            assert created_user.email_verified is False  # Default value

    def test_update_user(self, user_repo, mock_session, sample_user):
        """
        GIVEN user ID and update data
        WHEN update_user is called
        THEN it should update and return the user
        """
        # Setup
        query = mock_session.query.return_value
        query.filter.return_value.first.return_value = sample_user

        # Mock the BaseRepository.update method
        with patch.object(user_repo, "update") as mock_update:
            # Update data
            update_data = {
                "email": "updated@example.com",
                "is_admin": True,
                "organization": "Updated Org",
                "locale": "es-ES",
                "name": "Updated Name",
                "given_name": "Updated",
                "family_name": "Name",
                "email_verified": False,
            }

            # Execute
            result = user_repo.update_user(1, update_data)

            # Verify
            assert result == sample_user
            mock_session.query.assert_called_once_with(User)
            query.filter.assert_called_once()
            mock_update.assert_called_once_with(sample_user)

            # Check that all fields were updated
            assert sample_user.email == "updated@example.com"
            assert sample_user.is_admin is True
            assert sample_user.organization == "Updated Org"
            assert sample_user.locale == "es-ES"
            assert sample_user.name == "Updated Name"
            assert sample_user.given_name == "Updated"
            assert sample_user.family_name == "Name"
            assert sample_user.email_verified is False

    def test_update_user_not_found(self, user_repo, mock_session):
        """
        GIVEN a non-existent user ID
        WHEN update_user is called
        THEN it should return None
        """
        # Setup
        query = mock_session.query.return_value
        query.filter.return_value.first.return_value = None

        # Update data
        update_data = {"email": "updated@example.com"}

        # Execute
        result = user_repo.update_user(999, update_data)

        # Verify
        assert result is None
        mock_session.query.assert_called_once_with(User)
        query.filter.assert_called_once()

    def test_update_last_login(self, user_repo, mock_session, sample_user):
        """
        GIVEN a user ID
        WHEN update_last_login is called
        THEN it should update the user's last_login and return the user
        """
        # Setup
        query = mock_session.query.return_value
        query.filter.return_value.first.return_value = sample_user

        # Mock the BaseRepository.update method
        with patch.object(user_repo, "update") as mock_update:
            # Execute
            result = user_repo.update_last_login(1)

            # Verify
            assert result == sample_user
            mock_session.query.assert_called_once_with(User)
            query.filter.assert_called_once()
            mock_update.assert_called_once_with(sample_user)

            # Check that last_login was updated
            assert sample_user.last_login is not None
            assert isinstance(sample_user.last_login, datetime)

    def test_update_last_login_not_found(self, user_repo, mock_session):
        """
        GIVEN a non-existent user ID
        WHEN update_last_login is called
        THEN it should return None
        """
        # Setup
        query = mock_session.query.return_value
        query.filter.return_value.first.return_value = None

        # Execute
        result = user_repo.update_last_login(999)

        # Verify
        assert result is None
        mock_session.query.assert_called_once_with(User)
        query.filter.assert_called_once()

    def test_delete_user(self, user_repo, mock_session, sample_user):
        """
        GIVEN a valid user ID
        WHEN delete_user is called
        THEN it should delete the user and return True
        """
        # Setup
        query = mock_session.query.return_value
        query.filter.return_value.first.return_value = sample_user

        # Execute
        result = user_repo.delete_user(1)

        # Verify
        assert result is True
        mock_session.query.assert_called_once_with(User)
        query.filter.assert_called_once()
        mock_session.delete.assert_called_once_with(sample_user)
        mock_session.commit.assert_called_once()

    def test_delete_user_not_found(self, user_repo, mock_session):
        """
        GIVEN a non-existent user ID
        WHEN delete_user is called
        THEN it should return False
        """
        # Setup
        query = mock_session.query.return_value
        query.filter.return_value.first.return_value = None

        # Execute
        result = user_repo.delete_user(999)

        # Verify
        assert result is False
        mock_session.query.assert_called_once_with(User)
        query.filter.assert_called_once()
        mock_session.delete.assert_not_called()
        mock_session.commit.assert_not_called()

    def test_get_all_users(self, user_repo, mock_session, sample_user):
        """
        GIVEN users in the database
        WHEN get_all_users is called
        THEN it should return all users
        """
        # Setup
        query = mock_session.query.return_value
        query.order_by.return_value.all.return_value = [sample_user]

        # Execute
        result = user_repo.get_all_users()

        # Verify
        assert result == [sample_user]
        mock_session.query.assert_called_once_with(User)
        query.order_by.assert_called_once()
        query.order_by.return_value.all.assert_called_once()

    def test_create_social_auth(self, user_repo, mock_session, sample_social_auth):
        """
        GIVEN social auth data
        WHEN create_social_auth is called
        THEN it should create and return a new social auth association
        """
        # Setup
        mock_session.add.return_value = None

        # Social auth data
        social_auth_data = {
            "user_id": 1,
            "provider": "github",
            "provider_user_id": "github123",
            "provider_name": "GitHub",
            "extra_data": {"avatar_url": "https://example.com/avatar.png"},
        }

        # Need to patch the SocialAuthAssociation constructor
        with patch("database.repositories.user.SocialAuthAssociation", return_value=sample_social_auth):
            # Execute
            result = user_repo.create_social_auth(social_auth_data)

            # Verify
            assert result == sample_social_auth
            mock_session.add.assert_called_once_with(sample_social_auth)
            mock_session.commit.assert_called_once()

    def test_get_social_auth(self, user_repo, mock_session, sample_social_auth):
        """
        GIVEN a provider and provider user ID
        WHEN get_social_auth is called
        THEN it should return the corresponding social auth association
        """
        # Setup
        query = mock_session.query.return_value
        query.filter.return_value.first.return_value = sample_social_auth

        # Execute
        result = user_repo.get_social_auth("github", "github123")

        # Verify
        assert result == sample_social_auth
        mock_session.query.assert_called_once_with(SocialAuthAssociation)
        query.filter.assert_called_once()
        query.filter.return_value.first.assert_called_once()

    def test_update_social_auth_last_used(self, user_repo, mock_session, sample_social_auth):
        """
        GIVEN a social auth ID
        WHEN update_social_auth_last_used is called
        THEN it should update the last_used timestamp and return the association
        """
        # Setup
        query = mock_session.query.return_value
        query.filter.return_value.first.return_value = sample_social_auth

        # Execute
        result = user_repo.update_social_auth_last_used(1)

        # Verify
        assert result == sample_social_auth
        mock_session.query.assert_called_once_with(SocialAuthAssociation)
        query.filter.assert_called_once()
        query.filter.return_value.first.assert_called_once()
        mock_session.commit.assert_called_once()

        # Check that last_used was updated
        assert sample_social_auth.last_used is not None
        assert isinstance(sample_social_auth.last_used, datetime)

    def test_update_social_auth_last_used_not_found(self, user_repo, mock_session):
        """
        GIVEN a non-existent social auth ID
        WHEN update_social_auth_last_used is called
        THEN it should return None
        """
        # Setup
        query = mock_session.query.return_value
        query.filter.return_value.first.return_value = None

        # Execute
        result = user_repo.update_social_auth_last_used(999)

        # Verify
        assert result is None
        mock_session.query.assert_called_once_with(SocialAuthAssociation)
        query.filter.assert_called_once()
        query.filter.return_value.first.assert_called_once()
        mock_session.commit.assert_not_called()

    def test_create_pkce_state(self, user_repo, mock_session, sample_pkce_state):
        """
        GIVEN PKCE state data
        WHEN create_pkce_state is called
        THEN it should create and return a new PKCE state
        """
        # Setup
        mock_session.add.return_value = None
        now = datetime.utcnow()
        expiration = now + timedelta(minutes=10)

        # Need to patch the PKCEState constructor
        with patch("database.repositories.user.PKCEState", return_value=sample_pkce_state):
            # Execute
            result = user_repo.create_pkce_state("random_state_string", "random_code_verifier", expiration)

            # Verify
            assert result == sample_pkce_state
            mock_session.add.assert_called_once_with(sample_pkce_state)
            mock_session.commit.assert_called_once()

    def test_get_pkce_state(self, user_repo, mock_session, sample_pkce_state):
        """
        GIVEN a state string
        WHEN get_pkce_state is called
        THEN it should return the corresponding PKCE state
        """
        # Setup
        query = mock_session.query.return_value
        query.filter.return_value.first.return_value = sample_pkce_state

        # Execute
        result = user_repo.get_pkce_state("random_state_string")

        # Verify
        assert result == sample_pkce_state
        mock_session.query.assert_called_once_with(PKCEState)
        query.filter.assert_called_once()
        query.filter.return_value.first.assert_called_once()

    def test_mark_pkce_state_used(self, user_repo, mock_session, sample_pkce_state):
        """
        GIVEN a PKCE state ID
        WHEN mark_pkce_state_used is called
        THEN it should mark the state as used and return it
        """
        # Setup
        query = mock_session.query.return_value
        query.filter.return_value.first.return_value = sample_pkce_state

        # Execute
        result = user_repo.mark_pkce_state_used(1)

        # Verify
        assert result == sample_pkce_state
        mock_session.query.assert_called_once_with(PKCEState)
        query.filter.assert_called_once()
        query.filter.return_value.first.assert_called_once()
        mock_session.commit.assert_called_once()

        # Check that used was updated
        assert sample_pkce_state.used is True

    def test_mark_pkce_state_used_not_found(self, user_repo, mock_session):
        """
        GIVEN a non-existent PKCE state ID
        WHEN mark_pkce_state_used is called
        THEN it should return None
        """
        # Setup
        query = mock_session.query.return_value
        query.filter.return_value.first.return_value = None

        # Execute
        result = user_repo.mark_pkce_state_used(999)

        # Verify
        assert result is None
        mock_session.query.assert_called_once_with(PKCEState)
        query.filter.assert_called_once()
        query.filter.return_value.first.assert_called_once()
        mock_session.commit.assert_not_called()
