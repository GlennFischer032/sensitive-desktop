"""
Tests for user service.
"""

import pytest
import sys
import os
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, ANY
import jwt

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

# Import the real UserService implementation
from services.user import UserService
from services.connections import BadRequestError, ForbiddenError, NotFoundError


class TestUserService:
    """Tests for the UserService."""

    @pytest.fixture
    def settings_mock(self):
        """Mock settings."""
        with patch("services.user.get_settings") as mock:
            settings = MagicMock()
            settings.OIDC_PROVIDER_URL = "https://oidc.example.com"
            settings.OIDC_CLIENT_ID = "test-client-id"
            settings.OIDC_CLIENT_SECRET = "test-client-secret"
            settings.OIDC_CALLBACK_URL = "https://app.example.com/callback"
            mock.return_value = settings
            yield settings

    @pytest.fixture
    def user_repo_mock(self):
        """Mock UserRepository."""
        with patch("services.user.UserRepository") as mock:
            mock_instance = MagicMock()

            # Mock user
            user = MagicMock()
            user.id = 1
            user.username = "testuser"
            user.email = "test@example.com"
            user.sub = "oidc-subject-12345"
            user.is_admin = False
            user.organization = "Test Org"
            user.given_name = "Test"
            user.family_name = "User"
            user.name = "Test User"
            user.locale = "en"
            user.email_verified = True
            user.created_at = datetime.utcnow()
            user.last_login = datetime.utcnow()

            # Mock social_auth associations
            assoc = MagicMock()
            assoc.id = 1
            assoc.provider = "oidc"
            assoc.provider_user_id = "oidc-subject-12345"
            assoc.provider_name = "OIDC Provider"
            assoc.created_at = datetime.utcnow()
            assoc.last_used = datetime.utcnow()
            user.social_auth = [assoc]

            # Mock methods
            mock_instance.get_by_username.return_value = user
            mock_instance.get_by_sub.return_value = user
            mock_instance.get_all_users.return_value = [user]
            mock_instance.create_user.return_value = user
            mock_instance.get_social_auth.return_value = assoc

            # Mock PKCE state
            pkce_state = MagicMock()
            pkce_state.code_verifier = "test-code-verifier"
            pkce_state.expires_at = datetime.utcnow() + timedelta(minutes=10)
            mock_instance.get_pkce_state.return_value = pkce_state

            # Return the mock instance
            mock.return_value = mock_instance
            yield mock_instance

    @pytest.fixture
    def requests_post_mock(self):
        """Mock requests.post."""
        with patch("services.user.requests.post") as mock:
            response_mock = MagicMock()
            response_mock.status_code = 200
            response_mock.json.return_value = {
                "access_token": "mock-access-token",
                "id_token": "mock-id-token",
                "token_type": "Bearer",
                "expires_in": 3600,
            }
            mock.return_value = response_mock
            yield mock

    @pytest.fixture
    def requests_get_mock(self):
        """Mock requests.get."""
        with patch("services.user.requests.get") as mock:
            response_mock = MagicMock()
            response_mock.status_code = 200
            response_mock.json.return_value = {
                "sub": "oidc-subject-12345",
                "email": "test@example.com",
                "name": "Test User",
                "given_name": "Test",
                "family_name": "User",
                "organization": "Test Org",
            }
            mock.return_value = response_mock
            yield mock

    @pytest.fixture
    def jwt_decode_mock(self):
        """Mock jwt.decode."""
        with patch("services.user.jwt.decode") as mock:
            mock.return_value = {
                "sub": "oidc-subject-12345",
                "email": "test@example.com",
                "name": "Test User",
                "given_name": "Test",
                "family_name": "User",
                "organization": "Test Org",
                "locale": "en",
                "email_verified": True,
            }
            yield mock

    @pytest.fixture
    def jwt_encode_mock(self):
        """Mock jwt.encode."""
        with patch("services.user.jwt.encode") as mock:
            mock.return_value = "mock-jwt-token"
            yield mock

    def test_generate_pkce_pair(self):
        """Test generating PKCE code verifier and challenge."""
        # Use the actual implementation for this test
        import secrets
        import hashlib
        import base64

        # Mock the secrets.token_urlsafe function to return a predictable value
        with patch("secrets.token_urlsafe", return_value="test_verifier_12345"):
            service = UserService()
            code_verifier, code_challenge = service.generate_pkce_pair()

            # Calculate the expected code challenge
            expected_challenge = (
                base64.urlsafe_b64encode(hashlib.sha256("test_verifier_12345".encode()).digest()).decode().rstrip("=")
            )

            # Assert
            assert code_verifier == "test_verifier_12345"
            assert code_challenge == expected_challenge

    def test_store_pkce_state(self, user_repo_mock):
        """Test storing PKCE state."""
        # Create a real service instance but with mocked dependencies
        service = UserService()
        state = "test-state"
        code_verifier = "test-code-verifier"
        session = MagicMock()

        # Call the method directly
        service.store_pkce_state(state, code_verifier, session)

        # Verify the repository method was called with correct args
        user_repo_mock.create_pkce_state.assert_called_once()
        args, _ = user_repo_mock.create_pkce_state.call_args
        assert args[0] == state
        assert args[1] == code_verifier
        assert isinstance(args[2], datetime)

    def test_get_pkce_verifier_success(self, user_repo_mock):
        """Test getting PKCE verifier successfully."""
        # Create a real service instance
        service = UserService()
        state = "test-state"
        session = MagicMock()

        # Set up the pkce_state mock
        pkce_state = MagicMock()
        pkce_state.code_verifier = "test-code-verifier"
        user_repo_mock.get_pkce_state.return_value = pkce_state

        # Act
        result = service.get_pkce_verifier(state, session)

        # Assert
        assert result == "test-code-verifier"
        user_repo_mock.get_pkce_state.assert_called_once_with(state)

    def test_get_pkce_verifier_not_found(self, user_repo_mock):
        """Test getting PKCE verifier that doesn't exist."""
        # Create a real service instance
        service = UserService()
        state = "invalid-state"
        session = MagicMock()

        # Setup mock to return None
        user_repo_mock.get_pkce_state.return_value = None

        # Act & Assert
        with pytest.raises(ValueError) as excinfo:
            service.get_pkce_verifier(state, session)

        assert "Invalid or expired state" in str(excinfo.value)
        user_repo_mock.get_pkce_state.assert_called_once_with(state)

    def test_initiate_oidc_login(self, settings_mock, user_repo_mock):
        """Test initiating OIDC login."""
        import secrets

        # Set up a predictable state token
        with patch("secrets.token_urlsafe", return_value="test-state-token"):
            # Arrange
            service = UserService()
            session = MagicMock()

            # Mock generate_pkce_pair to return predictable values
            with patch.object(
                service, "generate_pkce_pair", return_value=("test-code-verifier", "test-code-challenge")
            ):
                # Act
                result = service.initiate_oidc_login(session)

            # Assert
            assert "authorization_url" in result
            auth_url = result["authorization_url"]
            assert "https://oidc.example.com/authorize" in auth_url
            assert "response_type=code" in auth_url
            assert "client_id=test-client-id" in auth_url
            assert "redirect_uri=" in auth_url
            assert "code_challenge=test-code-challenge" in auth_url
            assert "state=test-state-token" in auth_url

            # Verify mock calls
            user_repo_mock.create_pkce_state.assert_called_once()

    def test_process_oidc_callback_success(
        self, user_repo_mock, requests_post_mock, jwt_decode_mock, jwt_encode_mock, requests_get_mock
    ):
        """Test processing OIDC callback successfully."""
        # Arrange
        service = UserService()
        code = "test-authorization-code"
        state = "test-state"
        app_secret_key = "test-app-secret"
        session = MagicMock()

        # Setup mocks
        pkce_state = MagicMock()
        pkce_state.code_verifier = "test-code-verifier"
        user_repo_mock.get_pkce_state.return_value = pkce_state

        # JWT decode should return user info with the correct sub
        jwt_decode_mock.return_value = {
            "sub": "oidc-subject-12345",
            "email": "test@example.com",
            "name": "Test User",
            "given_name": "Test",
            "family_name": "User",
            "organization": "Test Org",
        }

        # Act
        result = service.process_oidc_callback(code, state, app_secret_key, session)

        # Assert
        assert "token" in result
        assert "user" in result
        assert result["user"]["username"] == "testuser"

        # Verify mock calls
        user_repo_mock.get_pkce_state.assert_called_once_with(state)
        requests_post_mock.assert_called_once()
        jwt_decode_mock.assert_called_once()
        jwt_encode_mock.assert_called_once()

    def test_process_oidc_callback_missing_parameters(self):
        """Test processing OIDC callback with missing parameters."""
        # Arrange
        service = UserService()
        session = MagicMock()

        # Act & Assert
        with pytest.raises(BadRequestError) as excinfo:
            service.process_oidc_callback(None, "test-state", "test-app-secret", session)

        assert "Missing required parameters" in str(excinfo.value)

    def test_process_oidc_callback_invalid_state(self, user_repo_mock):
        """Test processing OIDC callback with invalid state."""
        # Arrange
        service = UserService()
        code = "test-authorization-code"
        state = "invalid-state"
        app_secret_key = "test-app-secret"
        session = MagicMock()

        # Setup mock to return None for state
        user_repo_mock.get_pkce_state.return_value = None

        # Act & Assert
        with pytest.raises(BadRequestError) as excinfo:
            service.process_oidc_callback(code, state, app_secret_key, session)

        assert "Invalid or expired state" in str(excinfo.value)

    def test_process_oidc_callback_token_exchange_error(self, user_repo_mock, requests_post_mock):
        """Test processing OIDC callback with token exchange error."""
        # Arrange
        service = UserService()
        code = "test-authorization-code"
        state = "test-state"
        app_secret_key = "test-app-secret"
        session = MagicMock()

        # Setup mock for pkce_state
        pkce_state = MagicMock()
        pkce_state.code_verifier = "test-code-verifier"
        user_repo_mock.get_pkce_state.return_value = pkce_state

        # Setup mock to return error response
        response_mock = MagicMock()
        response_mock.status_code = 400
        response_mock.text = "invalid_grant"
        requests_post_mock.return_value = response_mock

        # Act & Assert
        with pytest.raises(BadRequestError) as excinfo:
            service.process_oidc_callback(code, state, app_secret_key, session)

        assert "Token exchange failed" in str(excinfo.value)

    def test_remove_user_success(self, user_repo_mock):
        """Test removing a user successfully."""
        # Arrange
        service = UserService()
        username = "testuser"
        current_user = MagicMock()
        current_user.username = "admin"  # Different from the user being removed
        session = MagicMock()

        # Act
        result = service.remove_user(username, current_user, session)

        # Assert
        assert "message" in result
        assert "User removed successfully" in result["message"]

        # Verify mock calls
        user_repo_mock.get_by_username.assert_called_once_with(username)
        user_repo_mock.delete_user.assert_called_once_with(1)  # The user ID

    def test_remove_user_missing_username(self):
        """Test removing a user with missing username."""
        # Arrange
        service = UserService()
        current_user = MagicMock()
        current_user.username = "admin"
        session = MagicMock()

        # Act & Assert
        with pytest.raises(BadRequestError) as excinfo:
            service.remove_user(None, current_user, session)

        assert "Missing username" in str(excinfo.value)

    def test_remove_user_self(self):
        """Test removing the current user (self)."""
        # Arrange
        service = UserService()
        username = "admin"
        current_user = MagicMock()
        current_user.username = "admin"  # Same as the user being removed
        session = MagicMock()

        # Act & Assert
        with pytest.raises(ForbiddenError) as excinfo:
            service.remove_user(username, current_user, session)

        assert "cannot remove your own account" in str(excinfo.value)

    def test_remove_user_not_found(self, user_repo_mock):
        """Test removing a non-existent user."""
        # Arrange
        service = UserService()
        username = "nonexistent"
        current_user = MagicMock()
        current_user.username = "admin"
        session = MagicMock()

        # Setup mock to return None
        user_repo_mock.get_by_username.return_value = None

        # Act & Assert
        with pytest.raises(NotFoundError) as excinfo:
            service.remove_user(username, current_user, session)

        assert "User not found" in str(excinfo.value)

    def test_create_user_success(self, user_repo_mock):
        """Test creating a user successfully."""
        # Arrange
        service = UserService()
        data = {"username": "newuser", "sub": "oidc-subject-67890", "is_admin": False}
        session = MagicMock()

        # Setup mock to return None for existing users check
        user_repo_mock.get_by_username.return_value = None
        user_repo_mock.get_by_sub.return_value = None

        # Mock the create_user method
        new_user = MagicMock()
        new_user.id = 2
        new_user.username = "newuser"
        new_user.is_admin = False
        new_user.created_at = datetime.utcnow()
        user_repo_mock.create_user.return_value = new_user

        # Act
        result = service.create_user(data, session)

        # Assert
        assert "id" in result
        assert result["username"] == "newuser"
        assert result["is_admin"] is False
        assert "message" in result
        assert "User created successfully" in result["message"]

        # Verify mock calls
        user_repo_mock.get_by_username.assert_called_once_with("newuser")
        user_repo_mock.get_by_sub.assert_called_once_with("oidc-subject-67890")
        user_repo_mock.create_user.assert_called_once()

    def test_create_user_missing_data(self):
        """Test creating a user with missing data."""
        # Arrange
        service = UserService()
        session = MagicMock()

        # Act & Assert - missing data
        with pytest.raises(BadRequestError) as excinfo:
            service.create_user(None, session)

        assert "Missing request data" in str(excinfo.value)

    def test_create_user_already_exists(self, user_repo_mock):
        """Test creating a user that already exists."""
        # Arrange
        service = UserService()
        data = {"username": "testuser", "sub": "oidc-subject-12345"}
        session = MagicMock()

        # Setup mock to return existing user
        existing_user = MagicMock()
        existing_user.username = "testuser"
        existing_user.sub = "oidc-subject-12345"
        user_repo_mock.get_by_username.return_value = existing_user

        # Act & Assert
        with pytest.raises(BadRequestError) as excinfo:
            service.create_user(data, session)

        assert "Username already exists" in str(excinfo.value)

    def test_list_users(self, user_repo_mock):
        """Test listing all users."""
        # Arrange
        service = UserService()
        session = MagicMock()

        # Setup mock to return list of users
        user1 = MagicMock()
        user1.id = 1
        user1.username = "testuser1"
        user1.email = "test1@example.com"
        user1.is_admin = False
        user1.organization = "Test Org"
        user1.created_at = datetime.utcnow()
        user1.last_login = datetime.utcnow()
        user1.sub = "sub1"
        user1.given_name = "Test1"
        user1.family_name = "User1"
        user1.name = "Test1 User1"
        user1.locale = "en"
        user1.email_verified = True

        user2 = MagicMock()
        user2.id = 2
        user2.username = "testuser2"
        user2.email = "test2@example.com"
        user2.is_admin = True
        user2.organization = "Admin Org"
        user2.created_at = datetime.utcnow()
        user2.last_login = datetime.utcnow()
        user2.sub = "sub2"
        user2.given_name = "Test2"
        user2.family_name = "User2"
        user2.name = "Test2 User2"
        user2.locale = "en"
        user2.email_verified = True

        user_repo_mock.get_all_users.return_value = [user1, user2]

        # Act
        result = service.list_users(session)

        # Assert
        assert "users" in result
        assert len(result["users"]) == 2
        assert result["users"][0]["username"] == "testuser1"
        assert result["users"][1]["username"] == "testuser2"

        # Verify mock calls
        user_repo_mock.get_all_users.assert_called_once()

    def test_get_user_success(self, user_repo_mock):
        """Test getting a user successfully."""
        # Arrange
        service = UserService()
        username = "testuser"
        session = MagicMock()

        # Setup mock user with social_auth
        user = MagicMock()
        user.id = 1
        user.username = "testuser"
        user.email = "test@example.com"
        user.is_admin = False
        user.organization = "Test Org"
        user.sub = "oidc-subject-12345"
        user.given_name = "Test"
        user.family_name = "User"
        user.name = "Test User"
        user.locale = "en"
        user.email_verified = True
        user.created_at = datetime.utcnow()
        user.last_login = datetime.utcnow()

        # Social auth association
        assoc = MagicMock()
        assoc.provider = "oidc"
        assoc.provider_user_id = "oidc-subject-12345"
        assoc.provider_name = "OIDC Provider"
        assoc.created_at = datetime.utcnow()
        assoc.last_used = datetime.utcnow()
        user.social_auth = [assoc]

        user_repo_mock.get_by_username.return_value = user

        # Act
        result = service.get_user(username, session)

        # Assert
        assert "user" in result
        assert result["user"]["username"] == "testuser"
        assert result["user"]["email"] == "test@example.com"
        assert "auth_providers" in result["user"]
        assert len(result["user"]["auth_providers"]) == 1

        # Verify mock calls
        user_repo_mock.get_by_username.assert_called_once_with(username)

    def test_get_user_not_found(self, user_repo_mock):
        """Test getting a non-existent user."""
        # Arrange
        service = UserService()
        username = "nonexistent"
        session = MagicMock()

        # Setup mock to return None
        user_repo_mock.get_by_username.return_value = None

        # Act & Assert
        with pytest.raises(NotFoundError) as excinfo:
            service.get_user(username, session)

        assert "User not found" in str(excinfo.value)
