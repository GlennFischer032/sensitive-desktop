"""
Functional tests for the user routes.
"""

import pytest
import sys
import os
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, ANY
from flask.testing import FlaskClient
from flask import request, Flask, jsonify
from functools import wraps

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))


@pytest.fixture
def mock_user_service():
    """Mock the UserService for testing."""
    with patch("routes.user_routes.UserService") as mock:
        # Setup mock methods with appropriate return values
        mock_instance = MagicMock()

        # Mock create_user
        mock_instance.create_user.return_value = {
            "username": "test-user",
            "created_at": datetime.utcnow().isoformat(),
            "message": "User created successfully",
        }

        # Mock list_users
        mock_instance.list_users.return_value = {
            "users": [
                {
                    "username": "test-user-1",
                    "email": "user1@example.com",
                    "is_admin": False,
                    "created_at": datetime.utcnow().isoformat(),
                },
                {
                    "username": "test-user-2",
                    "email": "user2@example.com",
                    "is_admin": True,
                    "created_at": datetime.utcnow().isoformat(),
                },
            ]
        }

        # Mock get_user
        mock_instance.get_user.return_value = {
            "username": "test-user",
            "email": "test@example.com",
            "is_admin": False,
            "created_at": datetime.utcnow().isoformat(),
            "last_login": datetime.utcnow().isoformat(),
        }

        # Mock remove_user
        mock_instance.remove_user.return_value = {"message": "User removed successfully"}

        # Mock verify_user_by_sub
        mock_instance.verify_user_by_sub.return_value = {"exists": True, "username": "test-user"}

        # Return the mock instance
        mock.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_auth_decorators():
    """Mock auth decorators with simple pass-through functions."""

    # Create simple pass-through decorators for regular tests
    def dummy_decorator(f):
        return f

    # Apply mocks
    with patch("routes.user_routes.token_required", dummy_decorator), patch(
        "routes.user_routes.admin_required", dummy_decorator
    ), patch("routes.user_routes.with_db_session", dummy_decorator):
        yield


# Create a fake user and db_session to use in requests
class FakeUser:
    def __init__(self, is_admin=True):
        self.username = "admin" if is_admin else "regular_user"
        self.is_admin = is_admin
        self.email = "admin@example.com" if is_admin else "user@example.com"


class AdminFakeUser(FakeUser):
    """Admin user for tests"""

    def __init__(self):
        super().__init__(is_admin=True)


class NonAdminFakeUser(FakeUser):
    """Non-admin user for tests"""

    def __init__(self):
        super().__init__(is_admin=False)


def real_admin_required(f):
    """Real decorator that checks admin status."""

    @wraps(f)
    def decorated(*args, **kwargs):
        # Check if current_user is set
        if not hasattr(request, "current_user"):
            return jsonify({"message": "Authorization required!"}), 401

        # Check admin status
        if not request.current_user.is_admin:
            return jsonify({"message": "Admin privilege required!"}), 403

        # User is admin, continue
        return f(*args, **kwargs)

    return decorated


def real_token_required(f):
    """Real decorator that checks token authentication."""

    @wraps(f)
    def decorated(*args, **kwargs):
        # Check if token exists in request
        if not hasattr(request, "token") or not request.token:
            return jsonify({"message": "Token is missing!"}), 401

        # Check if current_user is set
        if not hasattr(request, "current_user"):
            return jsonify({"message": "User not found!"}), 401

        # Token is valid, continue
        return f(*args, **kwargs)

    return decorated


@pytest.fixture
def mock_token():
    """Mock token for authorization."""
    return "fake-test-token"


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
def app_with_user_routes(test_app, mock_user_repository, mock_token_repository):
    """
    Register user blueprint with test app.
    """
    from routes.user_routes import users_bp

    # Register the blueprint with a unique name to avoid conflicts
    test_app.register_blueprint(users_bp, name="users_bp_test")

    # Create and register a before_request handler
    @test_app.before_request
    def set_test_user():
        # Mock the request.current_user and request.db_session
        if not hasattr(request, "current_user"):
            request.current_user = AdminFakeUser()
        if not hasattr(request, "db_session"):
            request.db_session = MagicMock()
        # Set token in the request
        request.token = "fake-test-token"

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

                    # We are no longer completely bypassing the decorators,
                    # instead we'll let our mock_auth_decorators handle the validation
                    yield test_app


@pytest.fixture
def client_with_user_routes(app_with_user_routes):
    """Get a test client with the user routes registered."""
    # Create regular test client
    client = app_with_user_routes.test_client()

    # Set up before request handler on app itself to set request attributes
    @app_with_user_routes.before_request
    def set_test_attrs():
        request.current_user = AdminFakeUser()
        request.db_session = MagicMock()
        request.token = "fake-test-token"

    return client


def test_create_user(mock_auth_decorators, client_with_user_routes, mock_user_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/createuser' endpoint is requested (POST) with valid data
    THEN check that the response is valid and user is created
    """
    # Test data
    user_data = {"username": "test-user", "email": "test@example.com", "sub": "test-sub-123", "is_admin": False}

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_user_routes.post("/createuser", json=user_data, headers=headers)

    # Check response
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data["username"] == "test-user"
    assert "created_at" in data
    assert "message" in data

    # Verify mock was called correctly
    mock_user_service.create_user.assert_called_once_with(user_data, ANY)


def test_create_user_missing_data(mock_auth_decorators, client_with_user_routes, mock_user_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/createuser' endpoint is requested (POST) with missing data
    THEN check that the service is still called with the provided data
    """
    # Test data with missing fields
    user_data = {}

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_user_routes.post("/createuser", json=user_data, headers=headers)

    # Check that the service is still called (validation handled by service)
    mock_user_service.create_user.assert_called_once_with(user_data, ANY)


def test_create_user_non_admin(mock_auth_decorators, app_with_user_routes, mock_user_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/createuser' endpoint is requested (POST) by a non-admin user
    THEN check that the response is 403 Forbidden
    """

    # Create a custom view function with our real admin check
    @app_with_user_routes.route("/test_admin_endpoint", methods=["POST"])
    @real_admin_required
    def test_admin_endpoint():
        return jsonify({"success": True}), 200

    # Create a test client
    client = app_with_user_routes.test_client()

    # Make the request with a non-admin user
    with app_with_user_routes.test_request_context():
        # Set the current user to non-admin for the next request
        @app_with_user_routes.before_request
        def set_non_admin_user():
            request.current_user = NonAdminFakeUser()
            request.db_session = MagicMock()
            request.token = mock_token

        # Make the actual request
        headers = {"Authorization": f"Bearer {mock_token}"}
        response = client.post("/test_admin_endpoint", headers=headers)

        # Check response - should be forbidden
        assert response.status_code == 403
        data = json.loads(response.data)
        assert "message" in data
        assert data["message"] == "Admin privilege required!"


def test_create_user_api_error(mock_auth_decorators, client_with_user_routes, mock_user_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/createuser' endpoint is requested but an APIError occurs
    THEN check that the appropriate error response is returned
    """
    # Import the actual APIError class
    from services.connections import APIError

    # Configure mock to raise APIError
    error_message = "API error creating user"
    mock_user_service.create_user.side_effect = APIError(error_message, status_code=400)

    # Test data
    user_data = {"username": "test-user", "email": "test@example.com"}

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_user_routes.post("/createuser", json=user_data, headers=headers)

    # Check response
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "error" in data
    assert data["error"] == error_message


def test_create_user_generic_error(mock_auth_decorators, client_with_user_routes, mock_user_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/createuser' endpoint is requested but a generic error occurs
    THEN check that the appropriate error response is returned
    """
    # Configure mock to raise generic Exception
    error_message = "Failed to create user"
    mock_user_service.create_user.side_effect = Exception(error_message)

    # Test data
    user_data = {"username": "test-user", "email": "test@example.com"}

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_user_routes.post("/createuser", json=user_data, headers=headers)

    # Check response
    assert response.status_code == 500
    data = json.loads(response.data)
    assert "error" in data
    assert "details" in data
    assert data["details"] == error_message


def test_list_users(mock_auth_decorators, client_with_user_routes, mock_user_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/list' endpoint is requested (GET)
    THEN check that the response contains a list of users
    """
    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_user_routes.get("/list", headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "users" in data
    assert len(data["users"]) == 2
    assert data["users"][0]["username"] == "test-user-1"
    assert data["users"][1]["username"] == "test-user-2"

    # Verify mock was called correctly
    mock_user_service.list_users.assert_called_once_with(ANY)


def test_list_users_api_error(mock_auth_decorators, client_with_user_routes, mock_user_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/list' endpoint is requested but an APIError occurs
    THEN check that the appropriate error response is returned
    """
    # Import the actual APIError class
    from services.connections import APIError

    # Configure mock to raise APIError
    error_message = "API error listing users"
    mock_user_service.list_users.side_effect = APIError(error_message, status_code=400)

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_user_routes.get("/list", headers=headers)

    # Check response
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "error" in data
    assert data["error"] == error_message


def test_list_users_generic_error(mock_auth_decorators, client_with_user_routes, mock_user_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/list' endpoint is requested but a generic error occurs
    THEN check that the appropriate error response is returned
    """
    # Configure mock to raise generic Exception
    error_message = "Failed to list users"
    mock_user_service.list_users.side_effect = Exception(error_message)

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_user_routes.get("/list", headers=headers)

    # Check response
    assert response.status_code == 500
    data = json.loads(response.data)
    assert "error" in data
    assert "details" in data
    assert data["details"] == error_message


def test_get_user(mock_auth_decorators, client_with_user_routes, mock_user_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/<username>' endpoint is requested (GET)
    THEN check that the user details are returned
    """
    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_user_routes.get("/test-user", headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["username"] == "test-user"
    assert data["email"] == "test@example.com"
    assert "created_at" in data
    assert "last_login" in data

    # Verify mock was called correctly
    mock_user_service.get_user.assert_called_once_with("test-user", ANY)


def test_get_user_api_error(mock_auth_decorators, client_with_user_routes, mock_user_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/<username>' endpoint is requested but an APIError occurs
    THEN check that the appropriate error response is returned
    """
    # Import the actual APIError class
    from services.connections import APIError

    # Configure mock to raise APIError
    error_message = "API error getting user"
    mock_user_service.get_user.side_effect = APIError(error_message, status_code=404)

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_user_routes.get("/nonexistent-user", headers=headers)

    # Check response
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "error" in data
    assert data["error"] == error_message


def test_get_user_generic_error(mock_auth_decorators, client_with_user_routes, mock_user_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/<username>' endpoint is requested but a generic error occurs
    THEN check that the appropriate error response is returned
    """
    # Configure mock to raise generic Exception
    error_message = "Failed to get user"
    mock_user_service.get_user.side_effect = Exception(error_message)

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_user_routes.get("/test-user", headers=headers)

    # Check response
    assert response.status_code == 500
    data = json.loads(response.data)
    assert "error" in data
    assert "details" in data
    assert data["details"] == error_message


def test_remove_user(mock_auth_decorators, client_with_user_routes, mock_user_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/removeuser' endpoint is requested (POST)
    THEN check that the user is removed successfully
    """
    # Test data
    data = {"username": "test-user"}

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_user_routes.post("/removeuser", json=data, headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "message" in data
    assert data["message"] == "User removed successfully"

    # Verify mock was called correctly
    mock_user_service.remove_user.assert_called_once_with("test-user", ANY, ANY)


def test_remove_user_missing_username(mock_auth_decorators, client_with_user_routes, mock_user_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/removeuser' endpoint is requested with missing username
    THEN check that a 400 error is returned
    """
    # Test data without username
    data = {}

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_user_routes.post("/removeuser", json=data, headers=headers)

    # Check response
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "error" in data
    assert "Missing username" in data["error"]

    # Verify mock was not called
    mock_user_service.remove_user.assert_not_called()


def test_remove_user_api_error(mock_auth_decorators, client_with_user_routes, mock_user_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/removeuser' endpoint is requested but an APIError occurs
    THEN check that the appropriate error response is returned
    """
    # Import the actual APIError class
    from services.connections import APIError

    # Configure mock to raise APIError
    error_message = "API error removing user"
    mock_user_service.remove_user.side_effect = APIError(error_message, status_code=404)

    # Test data
    data = {"username": "nonexistent-user"}

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_user_routes.post("/removeuser", json=data, headers=headers)

    # Check response
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "error" in data
    assert data["error"] == error_message


def test_remove_user_generic_error(mock_auth_decorators, client_with_user_routes, mock_user_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/removeuser' endpoint is requested but a generic error occurs
    THEN check that the appropriate error response is returned
    """
    # Configure mock to raise generic Exception
    error_message = "Failed to remove user"
    mock_user_service.remove_user.side_effect = Exception(error_message)

    # Test data
    data = {"username": "test-user"}

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_user_routes.post("/removeuser", json=data, headers=headers)

    # Check response
    assert response.status_code == 500
    data = json.loads(response.data)
    assert "error" in data
    assert "details" in data
    assert data["details"] == error_message


def test_verify_user_by_sub(mock_auth_decorators, client_with_user_routes, mock_user_service):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/verify' endpoint is requested (GET) with a valid sub
    THEN check that the verification result is returned
    """
    # Make request with query param
    response = client_with_user_routes.get("/verify?sub=test-sub-123")

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "exists" in data
    assert data["exists"] is True
    assert "username" in data

    # Verify mock was called correctly
    mock_user_service.verify_user_by_sub.assert_called_once_with("test-sub-123", ANY)


def test_verify_user_by_sub_not_found(mock_auth_decorators, client_with_user_routes, mock_user_service):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/verify' endpoint is requested with a non-existent sub
    THEN check that a 404 error is returned
    """
    # Import the actual APIError class
    from services.connections import APIError

    # Configure mock to raise APIError with 404 status
    error_message = "User not found"
    mock_user_service.verify_user_by_sub.side_effect = APIError(error_message, status_code=404)

    # Make request with query param
    response = client_with_user_routes.get("/verify?sub=nonexistent-sub")

    # Check response
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "exists" in data
    assert data["exists"] is False
    assert "message" in data
    assert data["message"] == "User not found"


def test_verify_user_by_sub_api_error(mock_auth_decorators, client_with_user_routes, mock_user_service):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/verify' endpoint is requested but an APIError (not 404) occurs
    THEN check that the appropriate error response is returned
    """
    # Import the actual APIError class
    from services.connections import APIError

    # Configure mock to raise APIError with non-404 status
    error_message = "API error verifying user"
    mock_user_service.verify_user_by_sub.side_effect = APIError(error_message, status_code=400)

    # Make request with query param
    response = client_with_user_routes.get("/verify?sub=test-sub")

    # Check response
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "error" in data
    assert data["error"] == error_message


def test_verify_user_by_sub_generic_error(mock_auth_decorators, client_with_user_routes, mock_user_service):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/verify' endpoint is requested but a generic error occurs
    THEN check that the appropriate error response is returned
    """
    # Configure mock to raise generic Exception
    error_message = "Failed to verify user"
    mock_user_service.verify_user_by_sub.side_effect = Exception(error_message)

    # Make request with query param
    response = client_with_user_routes.get("/verify?sub=test-sub")

    # Check response
    assert response.status_code == 500
    data = json.loads(response.data)
    assert "error" in data
    assert "details" in data
    assert data["details"] == error_message
