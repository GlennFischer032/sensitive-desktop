import pytest
import sys
import os
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from flask import Flask

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from services.token import TokenService
from services.connections import APIError, BadRequestError, NotFoundError
from schemas.token import TokenCreate


@pytest.fixture
def app():
    """Create a Flask app for testing."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret-key"
    return app


@pytest.fixture
def token_repo_mock():
    """Mock the TokenRepository."""
    with patch("services.token.TokenRepository") as mock:
        mock_instance = MagicMock()

        # Mock create_token
        token = MagicMock()
        token.token_id = "test-token-id"
        token.name = "Test Token"
        token.description = "Test description"
        token.created_at = datetime.utcnow()
        token.expires_at = datetime.utcnow() + timedelta(days=30)
        token.created_by = "admin_user"
        token.revoked = False
        mock_instance.create_token.return_value = token

        # Mock get_tokens_for_user
        token1 = MagicMock()
        token1.token_id = "test-token-id-1"
        token1.name = "Test Token 1"
        token1.description = "Test description 1"
        token1.created_at = datetime.utcnow()
        token1.expires_at = datetime.utcnow() + timedelta(days=30)
        token1.created_by = "admin_user"
        token1.revoked = False

        token2 = MagicMock()
        token2.token_id = "test-token-id-2"
        token2.name = "Test Token 2"
        token2.description = "Test description 2"
        token2.created_at = datetime.utcnow()
        token2.expires_at = datetime.utcnow() + timedelta(days=60)
        token2.created_by = "admin_user"
        token2.revoked = False

        mock_instance.get_tokens_for_user.return_value = [token1, token2]

        # Mock get_by_id
        mock_instance.get_by_id.return_value = token

        # Mock get_by_token_id
        mock_instance.get_by_token_id.return_value = token

        # Mock revoke_token
        mock_instance.revoke_token.return_value = None

        # Return the mock
        mock.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def user_repo_mock():
    """Mock the UserRepository."""
    with patch("services.token.UserRepository") as mock:
        mock_instance = MagicMock()

        # Mock get_by_username
        user = MagicMock()
        user.username = "admin_user"
        user.email = "admin@example.com"
        user.is_admin = True
        mock_instance.get_by_username.return_value = user

        # Return the mock
        mock.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def jwt_mock():
    """Mock the JWT encode/decode."""
    with patch("services.token.jwt") as mock:
        # Mock encode
        mock.encode.return_value = "mocked.jwt.token"

        # Mock decode
        mock.decode.return_value = {
            "sub": "token:test-token-id",
            "name": "admin_user",
            "token_id": "test-token-id",
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(days=30),
            "admin": True,
        }

        yield mock


def test_create_token(app, token_repo_mock, jwt_mock):
    """Test creating a new API token."""
    # Arrange
    service = TokenService()
    data = {"name": "Test Token", "description": "Token for testing", "expires_in_days": 30}
    current_user = MagicMock()
    current_user.username = "admin_user"
    session = MagicMock()

    # Run in app context
    with app.app_context():
        # Act
        result = service.create_token(data, current_user, session)

    # Assert
    assert result["token"] == "mocked.jwt.token"
    assert result["token_id"] == "test-token-id"
    assert result["name"] == "Test Token"
    assert "expires_at" in result
    assert result["created_by"] == "admin_user"

    # Verify mocks were called correctly
    token_repo_mock.create_token.assert_called_once_with(
        name="Test Token", description="Token for testing", expires_in_days=30, created_by="admin_user"
    )
    jwt_mock.encode.assert_called_once()


def test_create_token_missing_data(token_repo_mock):
    """Test creating a token with missing data."""
    # Arrange
    service = TokenService()
    data = None
    current_user = MagicMock()
    session = MagicMock()

    # Act & Assert
    with pytest.raises(BadRequestError, match="Missing request data"):
        service.create_token(data, current_user, session)


def test_create_token_invalid_data(token_repo_mock):
    """Test creating a token with invalid data."""
    # Arrange
    service = TokenService()
    data = {
        # Missing required fields
    }
    current_user = MagicMock()
    session = MagicMock()

    # Act & Assert
    with pytest.raises(BadRequestError):
        service.create_token(data, current_user, session)


def test_list_tokens(token_repo_mock):
    """Test listing tokens for a user."""
    # Arrange
    service = TokenService()
    current_user = MagicMock()
    current_user.username = "admin_user"
    session = MagicMock()

    # Act
    result = service.list_tokens(current_user, session)

    # Assert
    assert "tokens" in result
    assert len(result["tokens"]) == 2
    assert result["tokens"][0]["token_id"] == "test-token-id-1"
    assert result["tokens"][1]["token_id"] == "test-token-id-2"

    # Verify mock was called correctly
    token_repo_mock.get_tokens_for_user.assert_called_once_with("admin_user")


def test_revoke_token(token_repo_mock):
    """Test revoking a token."""
    # Arrange
    service = TokenService()
    token_id = "test-token-id"
    session = MagicMock()

    # Act
    result = service.revoke_token(token_id, session)

    # Assert
    assert "message" in result
    assert result["message"] == "Token successfully revoked"

    # Verify mocks were called correctly - only check revoke_token is called
    token_repo_mock.revoke_token.assert_called_once_with(token_id)


def test_revoke_token_not_found(token_repo_mock):
    """Test revoking a non-existent token."""
    # Arrange
    service = TokenService()
    token_id = "non-existent-token"
    session = MagicMock()

    # Mock token not found (ensure it matches the actual error being thrown)
    token_repo_mock.revoke_token.side_effect = NotFoundError(f"Token with ID {token_id} not found")

    # Act & Assert
    with pytest.raises(NotFoundError, match=f"Token with ID {token_id} not found"):
        service.revoke_token(token_id, session)


def test_api_login(app, token_repo_mock, user_repo_mock, jwt_mock):
    """Test API login with a valid token."""
    # Arrange
    service = TokenService()
    token = "valid.jwt.token"
    session = MagicMock()

    # Run in app context
    with app.app_context():
        # Act
        result = service.api_login(token, session)

    # Assert
    assert result["username"] == "admin_user"
    assert result["is_admin"] is True
    assert result["email"] == "admin@example.com"

    # Verify mocks were called correctly
    jwt_mock.decode.assert_called_once()
    token_repo_mock.get_by_token_id.assert_called_once_with("test-token-id")
    user_repo_mock.get_by_username.assert_called_once_with("admin_user")


def test_api_login_invalid_token(app, jwt_mock):
    """Test API login with an invalid token."""
    # Arrange
    service = TokenService()
    token = "invalid.jwt.token"
    session = MagicMock()

    # Mock invalid token (missing token_id)
    jwt_mock.decode.return_value = {
        "sub": "token:test-token-id",
        "name": "admin_user",
        # token_id is missing
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(days=30),
        "admin": True,
    }

    # Run in app context
    with app.app_context():
        # Act & Assert
        with pytest.raises(BadRequestError, match="Token is invalid"):
            service.api_login(token, session)


def test_api_login_token_not_found(app, token_repo_mock, jwt_mock):
    """Test API login with a token that doesn't exist in the database."""
    # Arrange
    service = TokenService()
    token = "valid.jwt.token"
    session = MagicMock()

    # Mock token not found in database
    token_repo_mock.get_by_token_id.return_value = None

    # Run in app context
    with app.app_context():
        # Act & Assert
        with pytest.raises(NotFoundError, match="Token with ID test-token-id not found"):
            service.api_login(token, session)


def test_api_login_revoked_token(app, token_repo_mock, jwt_mock):
    """Test API login with a revoked token."""
    # Arrange
    service = TokenService()
    token = "revoked.jwt.token"
    session = MagicMock()

    # Mock revoked token
    revoked_token = MagicMock()
    revoked_token.token_id = "test-token-id"
    revoked_token.revoked = True
    token_repo_mock.get_by_token_id.return_value = revoked_token

    # Run in app context
    with app.app_context():
        # Act & Assert
        with pytest.raises(BadRequestError, match="Token is revoked"):
            service.api_login(token, session)


def test_api_login_expired_token(app, token_repo_mock, jwt_mock):
    """Test API login with an expired token."""
    # Arrange
    service = TokenService()
    token = "expired.jwt.token"
    session = MagicMock()

    # Mock expired token
    expired_token = MagicMock()
    expired_token.token_id = "test-token-id"
    expired_token.revoked = False
    expired_token.expires_at = datetime.utcnow() - timedelta(days=1)  # Expired
    token_repo_mock.get_by_token_id.return_value = expired_token

    # Run in app context
    with app.app_context():
        # Act & Assert
        with pytest.raises(BadRequestError, match="Token is expired"):
            service.api_login(token, session)


def test_api_login_user_not_found(app, token_repo_mock, user_repo_mock, jwt_mock):
    """Test API login when the user doesn't exist."""
    # Arrange
    service = TokenService()
    token = "valid.jwt.token"
    session = MagicMock()

    # Mock user not found
    user_repo_mock.get_by_username.return_value = None

    # Run in app context
    with app.app_context():
        # Act & Assert
        with pytest.raises(NotFoundError, match="User with username admin_user not found"):
            service.api_login(token, session)
