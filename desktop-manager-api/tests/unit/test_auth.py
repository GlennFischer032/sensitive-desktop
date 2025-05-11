import pytest
import sys
import os
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
import jwt
from flask import Flask, jsonify, request

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from core.auth import token_required, admin_required


@pytest.fixture
def app():
    """Create a Flask app for testing."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret-key"

    # Define test routes
    @app.route("/protected")
    @token_required
    def protected():
        return jsonify({"message": "Access granted", "user": request.current_user.username})

    @app.route("/admin")
    @token_required
    @admin_required
    def admin_only():
        return jsonify({"message": "Admin access granted"})

    # Fix for token_required decorator - initialize token variable
    @app.before_request
    def initialize_token():
        request.token = None

    return app


@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()


@pytest.fixture
def user_mock():
    """Create a mock user."""
    user = MagicMock()
    user.username = "testuser"
    user.email = "test@example.com"
    user.is_admin = False
    return user


@pytest.fixture
def admin_user_mock():
    """Create a mock admin user."""
    admin = MagicMock()
    admin.username = "adminuser"
    admin.email = "admin@example.com"
    admin.is_admin = True
    return admin


@pytest.fixture
def valid_token(app):
    """Create a valid JWT token."""
    data = {"sub": "user:1", "name": "testuser", "exp": datetime.utcnow() + timedelta(minutes=15)}
    return jwt.encode(data, app.config["SECRET_KEY"], algorithm="HS256")


@pytest.fixture
def valid_api_token(app):
    """Create a valid API token."""
    data = {
        "sub": "token:test-token-id",
        "name": "testuser",
        "token_id": "test-token-id",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(minutes=15),
        "admin": False,
    }
    return jwt.encode(data, app.config["SECRET_KEY"], algorithm="HS256")


@pytest.fixture
def valid_admin_api_token(app):
    """Create a valid admin API token."""
    data = {
        "sub": "token:admin-token-id",
        "name": "adminuser",
        "token_id": "admin-token-id",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(minutes=15),
        "admin": True,
    }
    return jwt.encode(data, app.config["SECRET_KEY"], algorithm="HS256")


class TestTokenRequired:
    """Tests for the token_required decorator."""

    def test_invalid_token(self, client):
        """Test request with invalid token."""
        # Act
        response = client.get("/protected", headers={"Authorization": "Bearer invalid.token"})

        # Assert
        assert response.status_code == 401
        assert "Token is invalid" in response.get_json()["message"]

    @patch("core.auth.get_db_session")
    @patch("core.auth.UserRepository")
    def test_valid_user_token(self, user_repo_mock, session_mock, client, valid_token, user_mock):
        """Test request with valid user token."""
        # Arrange
        session_instance = MagicMock()
        session_mock.return_value.__enter__.return_value = session_instance

        repo_instance = MagicMock()
        user_repo_mock.return_value = repo_instance
        repo_instance.get_by_sub.return_value = user_mock

        # Act
        response = client.get("/protected", headers={"Authorization": f"Bearer {valid_token}"})

        # Assert
        assert response.status_code == 200
        assert response.get_json()["message"] == "Access granted"
        assert response.get_json()["user"] == "testuser"

        # Verify mocks
        repo_instance.get_by_sub.assert_called_once_with("user:1")

    @patch("core.auth.get_db_session")
    @patch("core.auth.TokenRepository")
    @patch("core.auth.UserRepository")
    def test_valid_api_token(self, user_repo_mock, token_repo_mock, session_mock, client, valid_api_token, user_mock):
        """Test request with valid API token."""
        # Arrange
        session_instance = MagicMock()
        session_mock.return_value.__enter__.return_value = session_instance

        token_repo_instance = MagicMock()
        token_repo_mock.return_value = token_repo_instance

        # Create mock token
        token = MagicMock()
        token.token_id = "test-token-id"
        token.created_by = "testuser"
        token.revoked = False
        token.expires_at = datetime.utcnow() + timedelta(days=1)
        token_repo_instance.get_by_token_id.return_value = token

        user_repo_instance = MagicMock()
        user_repo_mock.return_value = user_repo_instance
        user_repo_instance.get_by_username.return_value = user_mock

        # Act
        response = client.get("/protected", headers={"Authorization": f"Bearer {valid_api_token}"})

        # Assert
        assert response.status_code == 200
        assert response.get_json()["message"] == "Access granted"
        assert response.get_json()["user"] == "testuser"

        # Verify mocks
        token_repo_instance.get_by_token_id.assert_called_once_with("test-token-id")
        token_repo_instance.update_last_used.assert_called_once_with("test-token-id")
        user_repo_instance.get_by_username.assert_called_once_with("testuser")

    @patch("core.auth.get_db_session")
    @patch("core.auth.TokenRepository")
    def test_revoked_api_token(self, token_repo_mock, session_mock, client, valid_api_token):
        """Test request with revoked API token."""
        # Arrange
        session_instance = MagicMock()
        session_mock.return_value.__enter__.return_value = session_instance

        token_repo_instance = MagicMock()
        token_repo_mock.return_value = token_repo_instance

        # Create mock revoked token
        token = MagicMock()
        token.token_id = "test-token-id"
        token.created_by = "testuser"
        token.revoked = True
        token.expires_at = datetime.utcnow() + timedelta(days=1)
        token_repo_instance.get_by_token_id.return_value = token

        # Act
        response = client.get("/protected", headers={"Authorization": f"Bearer {valid_api_token}"})

        # Assert
        assert response.status_code == 401
        assert "Token is revoked" in response.get_json()["message"]

        # Verify mocks
        token_repo_instance.get_by_token_id.assert_called_once_with("test-token-id")
        token_repo_instance.update_last_used.assert_not_called()

    @patch("core.auth.get_db_session")
    @patch("core.auth.TokenRepository")
    def test_expired_api_token(self, token_repo_mock, session_mock, client, valid_api_token):
        """Test request with expired API token."""
        # Arrange
        session_instance = MagicMock()
        session_mock.return_value.__enter__.return_value = session_instance

        token_repo_instance = MagicMock()
        token_repo_mock.return_value = token_repo_instance

        # Create mock expired token
        token = MagicMock()
        token.token_id = "test-token-id"
        token.created_by = "testuser"
        token.revoked = False
        token.expires_at = datetime.utcnow() - timedelta(days=1)  # Expired
        token_repo_instance.get_by_token_id.return_value = token

        # Act
        response = client.get("/protected", headers={"Authorization": f"Bearer {valid_api_token}"})

        # Assert
        assert response.status_code == 401
        assert "Token is expired" in response.get_json()["message"]

        # Verify mocks
        token_repo_instance.get_by_token_id.assert_called_once_with("test-token-id")
        token_repo_instance.update_last_used.assert_not_called()

    @patch("core.auth.get_db_session")
    @patch("core.auth.TokenRepository")
    def test_missing_token_in_db(self, token_repo_mock, session_mock, client, valid_api_token):
        """Test request with token that doesn't exist in the database."""
        # Arrange
        session_instance = MagicMock()
        session_mock.return_value.__enter__.return_value = session_instance

        token_repo_instance = MagicMock()
        token_repo_mock.return_value = token_repo_instance
        token_repo_instance.get_by_token_id.return_value = None  # Token not found in DB

        # Act
        response = client.get("/protected", headers={"Authorization": f"Bearer {valid_api_token}"})

        # Assert
        assert response.status_code == 401
        assert "Token is invalid" in response.get_json()["message"]

        # Verify mocks
        token_repo_instance.get_by_token_id.assert_called_once_with("test-token-id")
        token_repo_instance.update_last_used.assert_not_called()


class TestAdminRequired:
    """Tests for the admin_required decorator."""

    @patch("core.auth.get_db_session")
    @patch("core.auth.TokenRepository")
    @patch("core.auth.UserRepository")
    def test_admin_access_granted(
        self, user_repo_mock, token_repo_mock, session_mock, client, valid_admin_api_token, admin_user_mock
    ):
        """Test admin access with admin user."""
        # Arrange
        session_instance = MagicMock()
        session_mock.return_value.__enter__.return_value = session_instance

        token_repo_instance = MagicMock()
        token_repo_mock.return_value = token_repo_instance

        # Create mock token
        token = MagicMock()
        token.token_id = "admin-token-id"
        token.created_by = "adminuser"
        token.revoked = False
        token.expires_at = datetime.utcnow() + timedelta(days=1)
        token_repo_instance.get_by_token_id.return_value = token

        user_repo_instance = MagicMock()
        user_repo_mock.return_value = user_repo_instance
        user_repo_instance.get_by_username.return_value = admin_user_mock

        # Act
        response = client.get("/admin", headers={"Authorization": f"Bearer {valid_admin_api_token}"})

        # Assert
        assert response.status_code == 200
        assert response.get_json()["message"] == "Admin access granted"

    @patch("core.auth.get_db_session")
    @patch("core.auth.TokenRepository")
    @patch("core.auth.UserRepository")
    def test_admin_access_denied(
        self, user_repo_mock, token_repo_mock, session_mock, client, valid_api_token, user_mock
    ):
        """Test admin access with non-admin user."""
        # Arrange
        session_instance = MagicMock()
        session_mock.return_value.__enter__.return_value = session_instance

        token_repo_instance = MagicMock()
        token_repo_mock.return_value = token_repo_instance

        # Create mock token
        token = MagicMock()
        token.token_id = "test-token-id"
        token.created_by = "testuser"
        token.revoked = False
        token.expires_at = datetime.utcnow() + timedelta(days=1)
        token_repo_instance.get_by_token_id.return_value = token

        user_repo_instance = MagicMock()
        user_repo_mock.return_value = user_repo_instance
        user_repo_instance.get_by_username.return_value = user_mock

        # Act
        response = client.get("/admin", headers={"Authorization": f"Bearer {valid_api_token}"})

        # Assert
        assert response.status_code == 403
        assert "Admin privilege required" in response.get_json()["message"]
