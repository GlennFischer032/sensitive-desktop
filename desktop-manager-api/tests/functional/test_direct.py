"""
Direct tests for route handler functions without going through the Flask app.
This approach focuses on testing the logic of the handlers directly.
"""

import pytest
import sys
import os
from unittest.mock import patch, MagicMock
import json
from flask import Flask, Request, request

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))


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


# Create a token routes test class
class TokenRoutesTest:
    @staticmethod
    def setup_route_dependencies(app, mock_token_service):
        """Setup the dependencies for token route testing."""
        # Import handlers after dependencies are mocked
        from routes.token_routes import create_token, list_tokens, revoke_token, api_login

        # Create a test client
        with app.test_request_context():
            # Set up request with test data
            request.get_json = MagicMock(
                return_value={"name": "Test Token", "description": "Test description", "expires_in_days": 30}
            )
            request.current_user = MagicMock(username="admin", is_admin=True)
            request.db_session = MagicMock()

            # Return handlers and context
            return {
                "create_token": create_token,
                "list_tokens": list_tokens,
                "revoke_token": revoke_token,
                "api_login": api_login,
            }


def test_create_token_handler(test_app, mock_token_service):
    """Test create_token handler function directly."""
    with test_app.test_request_context():
        # Set up test dependencies
        with patch("routes.token_routes.TokenService") as token_service_class:
            token_service_class.return_value = mock_token_service

            # Import handler function
            from routes.token_routes import create_token

            # Patch request object
            with patch("routes.token_routes.request") as mock_request:
                mock_request.get_json.return_value = {
                    "name": "Test Token",
                    "description": "Test description",
                    "expires_in_days": 30,
                }
                mock_request.current_user = MagicMock(username="admin", is_admin=True)
                mock_request.db_session = MagicMock()

                # Call the handler function
                response, status_code = create_token()

                # Extract the response data
                response_data = json.loads(response.get_data())

                # Verify handler function returns the expected response
                assert status_code == 201
                assert response_data["token"] == "test.jwt.token"
                assert response_data["token_id"] == "test-token-id"
                assert response_data["name"] == "Test Token"

                # Verify TokenService was called correctly
                mock_token_service.create_token.assert_called_once_with(
                    mock_request.get_json(), mock_request.current_user, mock_request.db_session
                )


def test_list_tokens_handler(test_app, mock_token_service):
    """Test list_tokens handler function directly."""
    with test_app.test_request_context():
        # Set up test dependencies
        with patch("routes.token_routes.TokenService") as token_service_class:
            token_service_class.return_value = mock_token_service

            # Import handler function
            from routes.token_routes import list_tokens

            # Patch request object
            with patch("routes.token_routes.request") as mock_request:
                mock_request.current_user = MagicMock(username="admin", is_admin=True)
                mock_request.db_session = MagicMock()

                # Call the handler function
                response, status_code = list_tokens()

                # Extract the response data
                response_data = json.loads(response.get_data())

                # Verify handler function returns the expected response
                assert status_code == 200
                assert "tokens" in response_data
                assert len(response_data["tokens"]) == 2
                assert response_data["tokens"][0]["token_id"] == "token1"
                assert response_data["tokens"][1]["token_id"] == "token2"

                # Verify TokenService was called correctly
                mock_token_service.list_tokens.assert_called_once_with(
                    mock_request.current_user, mock_request.db_session
                )


def test_revoke_token_handler(test_app, mock_token_service):
    """Test revoke_token handler function directly."""
    with test_app.test_request_context():
        # Set up test dependencies
        with patch("routes.token_routes.TokenService") as token_service_class:
            token_service_class.return_value = mock_token_service

            # Import handler function
            from routes.token_routes import revoke_token

            # Patch request object
            with patch("routes.token_routes.request") as mock_request:
                mock_request.db_session = MagicMock()

                # Call the handler function with a token_id
                token_id = "test-token-id"
                response, status_code = revoke_token(token_id)

                # Extract the response data
                response_data = json.loads(response.get_data())

                # Verify handler function returns the expected response
                assert status_code == 200
                assert "message" in response_data
                assert response_data["message"] == "Token successfully revoked"

                # Verify TokenService was called correctly
                mock_token_service.revoke_token.assert_called_once_with(token_id, mock_request.db_session)


def test_api_login_handler_success(test_app, mock_token_service):
    """Test api_login handler function with valid token."""
    with test_app.test_request_context():
        # Set up test dependencies
        with patch("routes.token_routes.TokenService") as token_service_class:
            token_service_class.return_value = mock_token_service

            # Import handler function
            from routes.token_routes import api_login

            # Patch request object
            with patch("routes.token_routes.request") as mock_request:
                # Set up request with token
                mock_request.get_json.return_value = {"token": "valid.jwt.token"}
                mock_request.db_session = MagicMock()

                # Call the handler function
                response, status_code = api_login()

                # Extract the response data
                response_data = json.loads(response.get_data())

                # Verify handler function returns the expected response
                assert status_code == 200
                assert "username" in response_data
                assert response_data["username"] == "admin_user"
                assert response_data["is_admin"] is True

                # Verify TokenService was called correctly
                mock_token_service.api_login.assert_called_once_with("valid.jwt.token", mock_request.db_session)


def test_api_login_handler_missing_token(test_app, mock_token_service):
    """Test api_login handler function with missing token."""
    with test_app.test_request_context():
        # Set up test dependencies
        with patch("routes.token_routes.TokenService") as token_service_class:
            token_service_class.return_value = mock_token_service

            # Import handler function
            from routes.token_routes import api_login

            # Patch request object
            with patch("routes.token_routes.request") as mock_request:
                # Set up request with missing token
                mock_request.get_json.return_value = {}
                mock_request.db_session = MagicMock()

                # Call the handler function
                response, status_code = api_login()

                # Extract the response data
                response_data = json.loads(response.get_data())

                # Verify handler function returns the expected error response
                assert status_code == 400
                assert "error" in response_data
                assert response_data["error"] == "Token is required"

                # Verify TokenService was not called
                mock_token_service.api_login.assert_not_called()


def test_create_token_handler_error(test_app, mock_token_service):
    """Test create_token handler function when service raises an error."""
    with test_app.test_request_context():
        # Set up test dependencies
        with patch("routes.token_routes.TokenService") as token_service_class:
            token_service_class.return_value = mock_token_service

            # Configure mock to raise an error
            error_message = "Failed to create token"
            mock_token_service.create_token.side_effect = Exception(error_message)

            # Import handler function
            from routes.token_routes import create_token

            # Patch request object
            with patch("routes.token_routes.request") as mock_request:
                mock_request.get_json.return_value = {
                    "name": "Test Token",
                    "description": "Test description",
                    "expires_in_days": 30,
                }
                mock_request.current_user = MagicMock(username="admin", is_admin=True)
                mock_request.db_session = MagicMock()

                # Call the handler function
                response, status_code = create_token()

                # Extract the response data
                response_data = json.loads(response.get_data())

                # Verify handler function returns the expected error response
                assert status_code == 500
                assert "error" in response_data
                assert "Failed to create API token" in response_data["error"]
                assert error_message in response_data["details"]
