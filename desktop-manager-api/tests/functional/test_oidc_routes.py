import pytest
import sys
import os
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from flask.testing import FlaskClient
from flask import Flask, request, current_app

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))


@pytest.fixture
def mock_user_service_oidc():
    """Mock the UserService for OIDC testing."""
    with patch("routes.oidc_routes.UserService") as mock:
        # Setup mock methods with appropriate return values
        mock_instance = MagicMock()

        # Mock initiate_oidc_login
        mock_instance.initiate_oidc_login.return_value = {
            "authorization_url": "https://test-oidc-provider.com/auth?response_type=code&client_id=test-client&redirect_uri=http://localhost/callback&state=test-state&code_challenge=test-challenge&code_challenge_method=S256",
            "state": "test-state",
        }

        # Mock process_oidc_callback
        mock_instance.process_oidc_callback.return_value = {
            "username": "test_user",
            "token": "test.jwt.token",
            "is_admin": False,
            "expires_at": "2025-01-01T00:00:00",
        }

        # Return the mock instance
        mock.return_value = mock_instance
        yield mock_instance


# Create a fake user class
class FakeUser:
    def __init__(self):
        self.username = "admin"
        self.is_admin = True
        self.email = "admin@example.com"


@pytest.fixture
def mock_user_repository():
    """Mock the UserRepository."""
    with patch("database.repositories.user.UserRepository") as mock:
        mock_instance = MagicMock()
        # Mock get_by_sub to return a user
        mock_user = MagicMock()
        mock_user.username = "admin"
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
        mock_token.created_by = "admin"
        mock_instance.get_by_token_id.return_value = mock_token
        mock.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def app_with_oidc_routes(test_app, mock_user_repository, mock_token_repository):
    """
    Register OIDC blueprint with test app.
    """
    from routes.oidc_routes import oidc_bp

    # Register the blueprint with a unique name to avoid conflicts
    test_app.register_blueprint(oidc_bp, name="oidc_bp_test", url_prefix="/api")

    # Create and register a before_request handler
    @test_app.before_request
    def set_test_db_session():
        # Mock the request.db_session and current_user
        if not hasattr(request, "db_session"):
            request.db_session = MagicMock()
        if not hasattr(request, "current_user"):
            request.current_user = FakeUser()
        # Set token in the request
        request.token = "test-token"

    # Set the SECRET_KEY in app config
    test_app.config["SECRET_KEY"] = "test-secret-key"

    # Mock JWT decode to return valid payload
    with patch("jwt.decode") as mock_jwt_decode:
        # Configure mock to return a valid payload
        mock_jwt_decode.return_value = {
            "sub": "admin",
            "name": "admin",
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

                    # Mock the with_db_session decorator
                    with patch("routes.oidc_routes.with_db_session", lambda f: f), patch(
                        "core.auth.token_required", lambda f: f
                    ), patch("core.auth.admin_required", lambda f: f):
                        yield test_app


@pytest.fixture
def client_with_oidc_routes(app_with_oidc_routes):
    """Get a test client with the OIDC routes registered."""
    client = app_with_oidc_routes.test_client()
    client.environ_base["HTTP_AUTHORIZATION"] = "Bearer test-token"
    return client


def test_oidc_login(client_with_oidc_routes, mock_user_service_oidc):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/api/auth/oidc/login' endpoint is requested (GET)
    THEN check that the authorization URL is returned
    """
    # Make request
    response = client_with_oidc_routes.get("/api/auth/oidc/login")

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "authorization_url" in data
    assert "state" in data
    assert data["state"] == "test-state"

    # Verify mock was called correctly
    mock_user_service_oidc.initiate_oidc_login.assert_called_once()


def test_oidc_callback_success(client_with_oidc_routes, mock_user_service_oidc):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/api/auth/oidc/callback' endpoint is requested (POST) with valid data
    THEN check that the user authentication is successful
    """
    # Test data
    callback_data = {"code": "test-authorization-code", "state": "test-state"}

    # Make request
    response = client_with_oidc_routes.post("/api/auth/oidc/callback", json=callback_data)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "username" in data
    assert data["username"] == "test_user"
    assert "token" in data
    assert "is_admin" in data
    assert "expires_at" in data

    # Verify mock was called once
    mock_user_service_oidc.process_oidc_callback.assert_called_once()


def test_oidc_callback_missing_data(client_with_oidc_routes, mock_user_service_oidc):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/api/auth/oidc/callback' endpoint is requested (POST) without necessary data
    THEN check that an error is returned
    """
    # Make request with empty JSON
    response = client_with_oidc_routes.post("/api/auth/oidc/callback", json={})

    # Check response
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "error" in data
    assert "Missing request data" in data["error"]


def test_oidc_login_service_error(client_with_oidc_routes, mock_user_service_oidc):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/api/auth/oidc/login' endpoint is requested (GET) but the service raises an APIError
    THEN check that the error is handled correctly
    """
    # Configure mock to raise an APIError
    from services.connections import APIError

    mock_user_service_oidc.initiate_oidc_login.side_effect = APIError(
        message="Failed to initiate OIDC login", status_code=500
    )

    # Make request
    response = client_with_oidc_routes.get("/api/auth/oidc/login")

    # Check response
    assert response.status_code == 500
    data = json.loads(response.data)
    assert "error" in data
    assert data["error"] == "Failed to initiate OIDC login"


def test_oidc_callback_service_error(client_with_oidc_routes, mock_user_service_oidc):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/api/auth/oidc/callback' endpoint is requested (POST) but the service raises an APIError
    THEN check that the error is handled correctly
    """
    # Configure mock to raise an APIError
    from services.connections import APIError

    mock_user_service_oidc.process_oidc_callback.side_effect = APIError(
        message="Invalid authorization code", status_code=400
    )

    # Test data
    callback_data = {"code": "invalid-code", "state": "test-state"}

    # Make request
    response = client_with_oidc_routes.post("/api/auth/oidc/callback", json=callback_data)

    # Check response
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "error" in data
    assert data["error"] == "Invalid authorization code"
