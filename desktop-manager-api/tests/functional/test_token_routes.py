import pytest
import sys
import os
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from flask.testing import FlaskClient
from flask import Flask, request, g
import jwt

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))


@pytest.fixture
def mock_token_service():
    """Mock the TokenService for testing."""
    with patch("routes.token_routes.TokenService") as mock:
        # Setup mock methods with appropriate return values
        mock_instance = MagicMock()

        # Mock create_token
        mock_instance.create_token.return_value = {
            "token": "mocked.jwt.token",
            "token_id": "test-token-id",
            "name": "Test Token",
            "expires_at": (datetime.utcnow() + timedelta(days=30)).isoformat(),
            "created_by": "admin_user",
        }

        # Mock list_tokens
        mock_instance.list_tokens.return_value = {
            "tokens": [
                {
                    "token_id": "test-token-id-1",
                    "name": "Test Token 1",
                    "description": "Test description 1",
                    "created_at": datetime.utcnow().isoformat(),
                    "expires_at": (datetime.utcnow() + timedelta(days=30)).isoformat(),
                    "created_by": "admin_user",
                    "revoked": False,
                },
                {
                    "token_id": "test-token-id-2",
                    "name": "Test Token 2",
                    "description": "Test description 2",
                    "created_at": datetime.utcnow().isoformat(),
                    "expires_at": (datetime.utcnow() + timedelta(days=60)).isoformat(),
                    "created_by": "admin_user",
                    "revoked": False,
                },
            ]
        }

        # Mock revoke_token
        mock_instance.revoke_token.return_value = {"message": "Token successfully revoked"}

        # Mock api_login
        mock_instance.api_login.return_value = {
            "username": "admin_user",
            "is_admin": True,
            "email": "admin@example.com",
        }

        # Return the mock instance
        mock.return_value = mock_instance
        yield mock_instance


# Create a fake user class
class FakeUser:
    def __init__(self):
        self.username = "admin_user"
        self.is_admin = True
        self.email = "admin@example.com"


@pytest.fixture
def mock_user_repository():
    """Mock the UserRepository."""
    with patch("database.repositories.user.UserRepository") as mock:
        mock_instance = MagicMock()
        # Mock get_by_sub to return a user
        mock_user = MagicMock()
        mock_user.username = "admin_user"
        mock_user.is_admin = True
        mock_user.email = "admin@example.com"
        mock_instance.get_by_sub.return_value = mock_user
        mock.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_token_repository():
    """Mock the TokenRepository."""
    with patch("database.repositories.token.TokenRepository") as mock:
        mock_instance = MagicMock()
        # Mock get_by_token_id
        mock_token = MagicMock()
        mock_token.token_id = "test-token-id"
        mock_token.revoked = False
        mock_token.expires_at = datetime.utcnow() + timedelta(days=30)
        mock_token.created_by = "admin_user"
        mock_instance.get_by_token_id.return_value = mock_token
        mock.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def app_with_token_routes(test_app, mock_user_repository, mock_token_repository):
    """
    Register token blueprint with test app.
    """
    from routes.token_routes import token_bp

    # Register the blueprint with a unique name to avoid conflicts
    test_app.register_blueprint(token_bp, name="token_bp_test", url_prefix="/api/tokens")

    # Create and register a before_request handler
    @test_app.before_request
    def set_test_user():
        # Mock the request.current_user and request.db_session
        if not hasattr(request, "current_user"):
            request.current_user = FakeUser()
        if not hasattr(request, "db_session"):
            request.db_session = MagicMock()
        # Set token in the request
        request.token = "test-token"

    # Mock JWT decode to return valid payload
    with patch("jwt.decode") as mock_jwt_decode:
        # Configure mock to return a valid payload
        mock_jwt_decode.return_value = {
            "sub": "admin_user",
            "name": "admin_user",
            "is_admin": True,
            "exp": 1861872000,  # Far future timestamp
        }

        # Mock the get_db_session function
        with patch("core.auth.get_db_session") as mock_get_db_session:
            mock_session = MagicMock()
            mock_session.__enter__.return_value = mock_session
            mock_get_db_session.return_value = mock_session

            # Mock the UserRepository
            with patch("core.auth.UserRepository") as mock_user_repo_class:
                mock_user_repo_class.return_value = mock_user_repository

                # Mock the TokenRepository
                with patch("core.auth.TokenRepository") as mock_token_repo_class:
                    mock_token_repo_class.return_value = mock_token_repository

                    # Mock all required decorators
                    with patch("routes.token_routes.token_required", lambda f: f), patch(
                        "routes.token_routes.admin_required", lambda f: f
                    ), patch("routes.token_routes.with_db_session", lambda f: f), patch(
                        "core.auth.token_required", lambda f: f
                    ), patch("core.auth.admin_required", lambda f: f):
                        yield test_app


@pytest.fixture
def client_with_token_routes(app_with_token_routes):
    """Get a test client with the token routes registered."""
    # Create a test client with the API token in headers
    client = app_with_token_routes.test_client()
    client.environ_base["HTTP_AUTHORIZATION"] = "Bearer test-token"
    return client


def test_create_token(client_with_token_routes, mock_token_service):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/api/tokens' endpoint is requested (POST) with valid data
    THEN check that the response is valid and token is created
    """
    # Test data
    token_data = {"name": "Test Token", "description": "Token for testing", "expires_in_days": 30}

    # Make request
    response = client_with_token_routes.post("/api/tokens", json=token_data)

    # Check response
    assert response.status_code == 201
    data = json.loads(response.data)
    assert "token" in data
    assert data["name"] == "Test Token"
    assert "token_id" in data
    assert "expires_at" in data

    # Verify mock was called correctly
    mock_token_service.create_token.assert_called_once()


def test_list_tokens(client_with_token_routes, mock_token_service):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/api/tokens' endpoint is requested (GET)
    THEN check that the response contains a list of tokens
    """
    # Make request
    response = client_with_token_routes.get("/api/tokens")

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "tokens" in data
    assert len(data["tokens"]) == 2
    assert data["tokens"][0]["name"] == "Test Token 1"
    assert data["tokens"][1]["name"] == "Test Token 2"

    # Verify mock was called correctly
    mock_token_service.list_tokens.assert_called_once()


def test_revoke_token(client_with_token_routes, mock_token_service):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/api/tokens/{token_id}' endpoint is requested (DELETE)
    THEN check that the token is revoked successfully
    """
    # Make request
    response = client_with_token_routes.delete("/api/tokens/test-token-id")

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "message" in data
    assert data["message"] == "Token successfully revoked"

    # Verify mock was called correctly
    mock_token_service.revoke_token.assert_called_once()


def test_api_login(client_with_token_routes, mock_token_service):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/api/tokens/api-login' endpoint is requested (POST) with a valid token
    THEN check that user data is returned
    """
    # Test data
    login_data = {"token": "valid.jwt.token"}

    # Make request
    response = client_with_token_routes.post("/api/tokens/api-login", json=login_data)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "username" in data
    assert data["username"] == "admin_user"
    assert "is_admin" in data
    assert data["is_admin"] is True
    assert "email" in data

    # Verify mock was called correctly
    mock_token_service.api_login.assert_called_once()


def test_api_login_missing_token(client_with_token_routes):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/api/tokens/api-login' endpoint is requested (POST) without a token
    THEN check that an error is returned
    """
    # Test data (missing token)
    login_data = {}

    # Make request
    response = client_with_token_routes.post("/api/tokens/api-login", json=login_data)

    # Check response
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "error" in data
    assert "Token is required" in data["error"]
