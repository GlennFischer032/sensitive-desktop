"""
Direct tests for route handler functions without going through the Flask app.
This approach focuses on testing the logic of the handlers directly.
"""

import pytest
import sys
import os
from unittest.mock import patch, MagicMock
import json
import jwt
from flask import Flask, Request, request

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))


@pytest.fixture
def mock_test_request():
    """Create a mock request for testing handlers directly."""
    mock_req = MagicMock()
    mock_req.headers = {"Authorization": "Bearer fake-test-token"}
    mock_req.get_json.return_value = {"name": "Test Token", "description": "Test description", "expires_in_days": 30}
    mock_req.current_user = MagicMock(username="admin", is_admin=True)
    mock_req.db_session = MagicMock()
    mock_req.token = "fake-test-token"
    return mock_req


@pytest.fixture
def test_app():
    """Create a Flask app for testing."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret-key"
    return app


@pytest.fixture
def mock_token_service():
    """Create a mocked TokenService."""
    with patch("services.token.TokenService") as mock:
        mock_instance = MagicMock()

        # Mock create_token
        mock_instance.create_token.return_value = {
            "token": "test.jwt.token",
            "token_id": "test-token-id",
            "name": "Test Token",
            "expires_at": "2023-12-31T23:59:59Z",
            "created_by": "admin",
        }

        # Mock list_tokens
        mock_instance.list_tokens.return_value = {
            "tokens": [
                {
                    "token_id": "token1",
                    "name": "Token 1",
                    "created_at": "2023-01-01T12:00:00Z",
                    "expires_at": "2023-12-31T23:59:59Z",
                },
                {
                    "token_id": "token2",
                    "name": "Token 2",
                    "created_at": "2023-02-01T12:00:00Z",
                    "expires_at": "2023-12-31T23:59:59Z",
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

        mock.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_auth_token_required():
    """Mock the token_required decorator."""

    def token_required_mock(f):
        def decorated(*args, **kwargs):
            return f(*args, **kwargs)

        return decorated

    return token_required_mock


@pytest.fixture
def mock_with_db_session():
    """Mock the with_db_session decorator."""

    def with_db_session_mock(f):
        def decorated(*args, **kwargs):
            return f(*args, **kwargs)

        return decorated

    return with_db_session_mock


def test_create_token_handler(
    test_app, mock_token_service, mock_test_request, mock_auth_token_required, mock_with_db_session
):
    """Test create_token handler function directly."""
    with test_app.test_request_context():
        # Set up mocks
        with patch("routes.token_routes.TokenService") as token_service_class, patch(
            "routes.token_routes.request", mock_test_request
        ), patch("core.auth.token_required", mock_auth_token_required), patch(
            "database.core.session.with_db_session", mock_with_db_session
        ), patch("jwt.decode") as mock_jwt_decode:
            # Set up mocks
            token_service_class.return_value = mock_token_service
            mock_jwt_decode.return_value = {
                "sub": "admin",
                "name": "admin",
                "is_admin": True,
                "exp": 1861872000,  # Far future timestamp
            }

            # Import the handler function after patching
            from routes.token_routes import create_token

            # Unwrap the decorated function
            # Access the original function
            create_token_func = create_token.__wrapped__.__wrapped__.__wrapped__

            # Call the handler function directly
            response, status_code = create_token_func()

            # Extract the response data
            response_data = json.loads(response.data)

            # Verify handler function returns the expected response
            assert status_code == 201
            assert response_data["token"] == "test.jwt.token"
            assert response_data["token_id"] == "test-token-id"
            assert response_data["name"] == "Test Token"

            # Verify TokenService was called correctly
            mock_token_service.create_token.assert_called_once_with(
                mock_test_request.get_json(), mock_test_request.current_user, mock_test_request.db_session
            )


def test_list_tokens_handler(
    test_app, mock_token_service, mock_test_request, mock_auth_token_required, mock_with_db_session
):
    """Test list_tokens handler function directly."""
    with test_app.test_request_context():
        # Set up mocks
        with patch("routes.token_routes.TokenService") as token_service_class, patch(
            "routes.token_routes.request", mock_test_request
        ), patch("core.auth.token_required", mock_auth_token_required), patch(
            "database.core.session.with_db_session", mock_with_db_session
        ), patch("jwt.decode") as mock_jwt_decode:
            # Set up mocks
            token_service_class.return_value = mock_token_service
            mock_jwt_decode.return_value = {
                "sub": "admin",
                "name": "admin",
                "is_admin": True,
                "exp": 1861872000,  # Far future timestamp
            }

            # Import the handler function after patching
            from routes.token_routes import list_tokens

            # Unwrap the decorated function
            list_tokens_func = list_tokens.__wrapped__.__wrapped__.__wrapped__

            # Call the handler function directly
            response, status_code = list_tokens_func()

            # Extract the response data
            response_data = json.loads(response.data)

            # Verify handler function returns the expected response
            assert status_code == 200
            assert "tokens" in response_data
            assert len(response_data["tokens"]) == 2
            assert response_data["tokens"][0]["token_id"] == "token1"
            assert response_data["tokens"][1]["token_id"] == "token2"

            # Verify TokenService was called correctly
            mock_token_service.list_tokens.assert_called_once_with(
                mock_test_request.current_user, mock_test_request.db_session
            )


def test_api_login_handler_success(test_app, mock_token_service, mock_test_request, mock_with_db_session):
    """Test api_login handler function with valid token."""
    with test_app.test_request_context():
        # Set up mocks
        with patch("routes.token_routes.TokenService") as token_service_class, patch(
            "routes.token_routes.request", mock_test_request
        ), patch("database.core.session.with_db_session", mock_with_db_session):
            # Set up mocks
            token_service_class.return_value = mock_token_service
            mock_test_request.get_json.return_value = {"token": "valid.jwt.token"}

            # Import the handler function after patching
            from routes.token_routes import api_login

            # Unwrap the decorated function
            api_login_func = api_login.__wrapped__

            # Call the handler function directly
            response, status_code = api_login_func()

            # Extract the response data
            response_data = json.loads(response.data)

            # Verify handler function returns the expected response
            assert status_code == 200
            assert "username" in response_data
            assert response_data["username"] == "admin_user"
            assert response_data["is_admin"] is True

            # Verify TokenService was called correctly
            mock_token_service.api_login.assert_called_once_with("valid.jwt.token", mock_test_request.db_session)


def test_api_login_handler_missing_token(test_app, mock_token_service, mock_test_request, mock_with_db_session):
    """Test api_login handler function with missing token."""
    with test_app.test_request_context():
        # Set up mocks
        with patch("routes.token_routes.TokenService") as token_service_class, patch(
            "routes.token_routes.request", mock_test_request
        ), patch("database.core.session.with_db_session", mock_with_db_session):
            # Set up mocks
            token_service_class.return_value = mock_token_service
            mock_test_request.get_json.return_value = {}

            # Import the handler function after patching
            from routes.token_routes import api_login

            # Unwrap the decorated function
            api_login_func = api_login.__wrapped__

            # Call the handler function directly
            response, status_code = api_login_func()

            # Extract the response data
            response_data = json.loads(response.data)

            # Verify handler function returns the expected error response
            assert status_code == 400
            assert "error" in response_data
            assert response_data["error"] == "Token is required"

            # Verify TokenService was not called
            mock_token_service.api_login.assert_not_called()
