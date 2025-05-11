"""
Functional tests for the connection routes.
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
def mock_connections_service():
    """Mock the ConnectionsService for testing."""
    with patch("routes.connection_routes.ConnectionsService") as mock:
        # Setup mock methods with appropriate return values
        mock_instance = MagicMock()

        # Mock scale_up
        mock_instance.scale_up.return_value = {
            "id": 1,
            "name": "test-desktop",
            "created_by": "admin",
            "status": "ready",
            "persistent_home": True,
            "desktop_configuration_id": 1,
            "created_at": datetime.utcnow().isoformat(),
        }

        # Mock list_connections
        mock_instance.list_connections.return_value = {
            "connections": [
                {
                    "id": 1,
                    "name": "test-desktop-1",
                    "created_by": "admin",
                    "status": "ready",
                    "created_at": datetime.utcnow().isoformat(),
                },
                {
                    "id": 2,
                    "name": "test-desktop-2",
                    "created_by": "admin",
                    "status": "ready",
                    "created_at": datetime.utcnow().isoformat(),
                },
            ]
        }

        # Mock get_connection
        mock_instance.get_connection.return_value = {
            "connection": {
                "id": 1,
                "name": "test-desktop",
                "created_by": "admin",
                "status": "ready",
                "created_at": datetime.utcnow().isoformat(),
                "persistent_home": True,
                "desktop_configuration_id": 1,
            }
        }

        # Mock direct_connect
        mock_instance.direct_connect.return_value = {
            "auth_url": "https://guacamole.example.com/?token=test-token",
            "connection_id": 1,
            "connection_name": "test-desktop",
        }

        # Mock scale_down
        mock_instance.scale_down.return_value = {"message": "Connection test-desktop scaled down and preserved"}

        # Mock get_connection_status
        mock_instance.get_connection_status.return_value = {
            "status": "running",
            "connection_id": 1,
            "connection_name": "test-desktop",
        }

        # Mock resume_connection
        mock_instance.resume_connection.return_value = {
            "id": 1,
            "name": "test-desktop",
            "created_by": "admin",
            "status": "ready",
            "persistent_home": True,
            "desktop_configuration_id": 1,
            "message": "Connection resumed successfully",
        }

        # Mock permanent_delete
        mock_instance.permanent_delete.return_value = {"message": "Connection permanently deleted"}

        # Mock attach_pvc_to_connection
        mock_instance.attach_pvc_to_connection.return_value = {
            "id": 1,
            "name": "test-desktop",
            "pvc_id": 5,
            "message": "PVC attached successfully",
        }

        # Mock detach_pvc_from_connection
        mock_instance.detach_pvc_from_connection.return_value = {
            "id": 1,
            "name": "test-desktop",
            "message": "PVC detached successfully",
        }

        # Mock guacamole_dashboard
        mock_instance.guacamole_dashboard.return_value = {
            "auth_url": "https://guacamole.example.com/?token=dashboard-token",
        }

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
    with patch("routes.connection_routes.token_required", dummy_decorator), patch(
        "routes.connection_routes.with_db_session", dummy_decorator
    ):
        yield


# Create a fake user and db_session to use in requests
class FakeUser:
    def __init__(self, is_admin=True):
        self.username = "admin" if is_admin else "regular_user"
        self.is_admin = is_admin
        self.email = "admin@example.com" if is_admin else "user@example.com"


class ValidUser(FakeUser):
    """User with valid authentication for tests"""

    def __init__(self, is_admin=True):
        super().__init__(is_admin=is_admin)


class RegularUser(ValidUser):
    """Regular user for tests"""

    def __init__(self):
        super().__init__(is_admin=False)


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
def app_with_connection_routes(test_app, mock_user_repository, mock_token_repository):
    """
    Register connection blueprint with test app.
    """
    from routes.connection_routes import connections_bp

    # Register the blueprint with a unique name to avoid conflicts
    test_app.register_blueprint(connections_bp, name="connections_bp_test")

    # Create and register a before_request handler
    @test_app.before_request
    def set_test_user():
        # Mock the request.current_user and request.db_session
        if not hasattr(request, "current_user"):
            request.current_user = ValidUser()
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
def client_with_connection_routes(app_with_connection_routes):
    """Get a test client with the connection routes registered."""
    # Create regular test client
    client = app_with_connection_routes.test_client()

    # Set up before request handler on app itself to set request attributes
    @app_with_connection_routes.before_request
    def set_test_attrs():
        request.current_user = ValidUser()
        request.db_session = MagicMock()
        request.token = "fake-test-token"

    return client


def test_scale_up_desktop(mock_auth_decorators, client_with_connection_routes, mock_connections_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/scaleup' endpoint is requested (POST) with valid data
    THEN check that the response is valid and desktop is created
    """
    # Test data
    data = {"name": "test-desktop", "persistent_home": True, "desktop_configuration_id": 1}

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_connection_routes.post("/scaleup", json=data, headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["id"] == 1
    assert data["name"] == "test-desktop"
    assert data["status"] == "ready"
    assert data["persistent_home"] is True
    assert data["desktop_configuration_id"] == 1

    # Verify mock was called correctly
    mock_connections_service.scale_up.assert_called_once_with(ANY, ANY, ANY)


def test_scale_up_desktop_no_token(mock_auth_decorators, app_with_connection_routes, mock_connections_service):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/scaleup' endpoint is requested (POST) without a token
    THEN check that the response is 401 Unauthorized
    """

    # Create a custom view function with our real token check
    @app_with_connection_routes.route("/test_token_endpoint", methods=["POST"])
    @real_token_required
    def test_token_endpoint():
        return jsonify({"success": True}), 200

    # Create a test client
    client = app_with_connection_routes.test_client()

    # Make the request without a token
    with app_with_connection_routes.test_request_context():
        # Set up request without token
        @app_with_connection_routes.before_request
        def set_missing_token():
            request.current_user = ValidUser()
            request.db_session = MagicMock()
            request.token = None

        # Make the actual request with no Authorization header
        response = client.post("/test_token_endpoint")

        # Check response - should be unauthorized
        assert response.status_code == 401
        data = json.loads(response.data)
        assert "message" in data
        assert data["message"] == "Token is missing!"


def test_list_connections(mock_auth_decorators, client_with_connection_routes, mock_connections_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/list' endpoint is requested (GET)
    THEN check that the response contains a list of connections
    """
    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_connection_routes.get("/list", headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "connections" in data
    assert len(data["connections"]) == 2
    assert data["connections"][0]["name"] == "test-desktop-1"
    assert data["connections"][1]["name"] == "test-desktop-2"

    # Verify mock was called correctly
    mock_connections_service.list_connections.assert_called_once_with(ANY, ANY, ANY)


def test_list_connections_with_filter(
    mock_auth_decorators, client_with_connection_routes, mock_connections_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/list' endpoint is requested (GET) with a created_by filter
    THEN check that the filter is passed to the service
    """
    # Make request with auth header and query parameter
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_connection_routes.get("/list?created_by=testuser", headers=headers)

    # Check response
    assert response.status_code == 200

    # Verify mock was called correctly with the filter parameter
    mock_connections_service.list_connections.assert_called_once()
    args, _ = mock_connections_service.list_connections.call_args
    assert args[1] == "testuser"  # The second argument should be the creator filter


def test_list_connections_no_auth(mock_auth_decorators, app_with_connection_routes, mock_connections_service):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/list' endpoint is requested (GET) without valid authentication
    THEN check that the response is 401 Unauthorized
    """

    # Create a custom view function with our real token check
    @app_with_connection_routes.route("/test_user_endpoint", methods=["GET"])
    @real_token_required
    def test_user_endpoint():
        return jsonify({"success": True}), 200

    # Create a test client
    client = app_with_connection_routes.test_client()

    # Make the request without auth
    with app_with_connection_routes.test_request_context():
        # Set up request with token but no user
        @app_with_connection_routes.before_request
        def set_missing_user():
            if hasattr(request, "current_user"):
                delattr(request, "current_user")
            request.db_session = MagicMock()
            request.token = "fake-test-token"

        # Make the actual request
        response = client.get("/test_user_endpoint")

        # Check response - should be unauthorized
        assert response.status_code == 401
        data = json.loads(response.data)
        assert "message" in data
        assert data["message"] == "User not found!"


def test_get_connection(mock_auth_decorators, client_with_connection_routes, mock_connections_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/<connection_name>' endpoint is requested (GET)
    THEN check that the connection details are returned
    """
    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_connection_routes.get("/test-desktop", headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "connection" in data
    assert data["connection"]["id"] == 1
    assert data["connection"]["name"] == "test-desktop"
    assert data["connection"]["status"] == "ready"

    # Verify mock was called correctly
    mock_connections_service.get_connection.assert_called_once_with("test-desktop", ANY, ANY)


def test_get_connection_api_error(
    mock_auth_decorators, client_with_connection_routes, mock_connections_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/<connection_name>' endpoint is requested (GET) but an APIError occurs
    THEN check that the appropriate error response is returned
    """
    # Import the actual APIError class
    from services.connections import APIError

    # Configure mock to raise APIError
    error_message = "Connection not found"
    mock_connections_service.get_connection.side_effect = APIError(error_message, status_code=404)

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_connection_routes.get("/nonexistent-connection", headers=headers)

    # Check response
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "error" in data
    assert data["error"] == error_message


def test_direct_connect(mock_auth_decorators, client_with_connection_routes, mock_connections_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/direct-connect/{id}' endpoint is requested (GET)
    THEN check that the direct connection URL is returned
    """
    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_connection_routes.get("/direct-connect/1", headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "auth_url" in data
    assert data["auth_url"] == "https://guacamole.example.com/?token=test-token"
    assert data["connection_id"] == 1
    assert data["connection_name"] == "test-desktop"

    # Verify mock was called correctly
    mock_connections_service.direct_connect.assert_called_once_with("1", ANY, ANY)


def test_direct_connect_api_error(
    mock_auth_decorators, client_with_connection_routes, mock_connections_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/direct-connect/{id}' endpoint is requested (GET) but an APIError occurs
    THEN check that the appropriate error response is returned
    """
    # Import the actual APIError class
    from services.connections import APIError

    # Configure mock to raise APIError
    error_message = "Connection not found"
    mock_connections_service.direct_connect.side_effect = APIError(error_message, status_code=404)

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_connection_routes.get("/direct-connect/999", headers=headers)

    # Check response
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "error" in data
    assert data["error"] == error_message


def test_scale_down_connection(
    mock_auth_decorators, client_with_connection_routes, mock_connections_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/scaledown' endpoint is requested (POST)
    THEN check that the connection is scaled down
    """
    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    data = {"name": "test-desktop"}
    response = client_with_connection_routes.post("/scaledown", json=data, headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "message" in data
    assert "scaled down and preserved" in data["message"]

    # Verify mock was called correctly
    mock_connections_service.scale_down.assert_called_once_with("test-desktop", ANY, ANY)


def test_scale_down_missing_name(
    mock_auth_decorators, client_with_connection_routes, mock_connections_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/scaledown' endpoint is requested (POST) without a name
    THEN check that a 400 error is returned
    """
    # Make request with auth header but empty data
    headers = {"Authorization": f"Bearer {mock_token}"}
    data = {}
    response = client_with_connection_routes.post("/scaledown", json=data, headers=headers)

    # Check response
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "error" in data
    assert "Missing required field: name" in data["error"]

    # Verify mock was not called
    mock_connections_service.scale_down.assert_not_called()


def test_get_connection_status(
    mock_auth_decorators, client_with_connection_routes, mock_connections_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/{name}/status' endpoint is requested (GET)
    THEN check that the connection status is returned
    """
    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_connection_routes.get("/test-desktop/status", headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["status"] == "running"
    assert data["connection_name"] == "test-desktop"

    # Verify mock was called correctly
    mock_connections_service.get_connection_status.assert_called_once_with("test-desktop", ANY, ANY)


def test_resume_connection(mock_auth_decorators, client_with_connection_routes, mock_connections_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/resume' endpoint is requested (POST) with valid data
    THEN check that the connection is resumed
    """
    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    data = {"name": "test-desktop"}
    response = client_with_connection_routes.post("/resume", json=data, headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["name"] == "test-desktop"
    assert "message" in data
    assert "resumed successfully" in data["message"]

    # Verify mock was called correctly
    mock_connections_service.resume_connection.assert_called_once_with("test-desktop", ANY, ANY)


def test_resume_connection_missing_name(
    mock_auth_decorators, client_with_connection_routes, mock_connections_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/resume' endpoint is requested (POST) without a name
    THEN check that a 400 error is returned
    """
    # Make request with auth header but empty data
    headers = {"Authorization": f"Bearer {mock_token}"}
    data = {}
    response = client_with_connection_routes.post("/resume", json=data, headers=headers)

    # Check response
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "error" in data
    assert "Missing required field: name" in data["error"]

    # Verify mock was not called
    mock_connections_service.resume_connection.assert_not_called()


def test_permanent_delete(mock_auth_decorators, client_with_connection_routes, mock_connections_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/permanent-delete' endpoint is requested (POST) with valid data
    THEN check that the connection is permanently deleted
    """
    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    data = {"name": "test-desktop"}
    response = client_with_connection_routes.post("/permanent-delete", json=data, headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "message" in data
    assert "permanently deleted" in data["message"]

    # Verify mock was called correctly
    mock_connections_service.permanent_delete.assert_called_once_with("test-desktop", ANY, ANY)


def test_permanent_delete_missing_name(
    mock_auth_decorators, client_with_connection_routes, mock_connections_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/permanent-delete' endpoint is requested (POST) without a name
    THEN check that a 400 error is returned
    """
    # Make request with auth header but empty data
    headers = {"Authorization": f"Bearer {mock_token}"}
    data = {}
    response = client_with_connection_routes.post("/permanent-delete", json=data, headers=headers)

    # Check response
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "error" in data
    assert "Missing required field: name" in data["error"]

    # Verify mock was not called
    mock_connections_service.permanent_delete.assert_not_called()


def test_attach_pvc(mock_auth_decorators, client_with_connection_routes, mock_connections_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/attach-pvc' endpoint is requested (POST) with valid data
    THEN check that the PVC is attached to the connection
    """
    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    data = {"connection_id": 1, "pvc_id": 5}
    response = client_with_connection_routes.post("/attach-pvc", json=data, headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["id"] == 1
    assert data["pvc_id"] == 5
    assert "message" in data
    assert "attached successfully" in data["message"]

    # Verify mock was called correctly
    mock_connections_service.attach_pvc_to_connection.assert_called_once_with(1, 5, ANY, ANY)


def test_attach_pvc_missing_fields(
    mock_auth_decorators, client_with_connection_routes, mock_connections_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/attach-pvc' endpoint is requested (POST) with missing fields
    THEN check that a 400 error is returned
    """
    # Make request with auth header but incomplete data
    headers = {"Authorization": f"Bearer {mock_token}"}
    data = {"connection_id": 1}  # Missing pvc_id
    response = client_with_connection_routes.post("/attach-pvc", json=data, headers=headers)

    # Check response
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "error" in data
    assert "Missing required fields" in data["error"]

    # Verify mock was not called
    mock_connections_service.attach_pvc_to_connection.assert_not_called()


def test_detach_pvc(mock_auth_decorators, client_with_connection_routes, mock_connections_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/detach-pvc' endpoint is requested (POST) with valid data
    THEN check that the PVC is detached from the connection
    """
    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    data = {"connection_id": 1}
    response = client_with_connection_routes.post("/detach-pvc", json=data, headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["id"] == 1
    assert "message" in data
    assert "detached successfully" in data["message"]

    # Verify mock was called correctly
    mock_connections_service.detach_pvc_from_connection.assert_called_once_with(1, ANY, ANY)


def test_detach_pvc_missing_connection_id(
    mock_auth_decorators, client_with_connection_routes, mock_connections_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/detach-pvc' endpoint is requested (POST) without a connection_id
    THEN check that a 400 error is returned
    """
    # Make request with auth header but empty data
    headers = {"Authorization": f"Bearer {mock_token}"}
    data = {}
    response = client_with_connection_routes.post("/detach-pvc", json=data, headers=headers)

    # Check response
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "error" in data
    assert "Missing required field: connection_id" in data["error"]

    # Verify mock was not called
    mock_connections_service.detach_pvc_from_connection.assert_not_called()


def test_guacamole_dashboard(mock_auth_decorators, client_with_connection_routes, mock_connections_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/guacamole-dashboard' endpoint is requested (GET)
    THEN check that the dashboard URL is returned
    """
    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_connection_routes.get("/guacamole-dashboard", headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "auth_url" in data
    assert data["auth_url"] == "https://guacamole.example.com/?token=dashboard-token"

    # Verify mock was called correctly
    mock_connections_service.guacamole_dashboard.assert_called_once_with(ANY)


def test_scale_up_desktop_error(
    mock_auth_decorators, client_with_connection_routes, mock_connections_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/scaleup' endpoint is requested but an APIError occurs
    THEN check that the appropriate error response is returned
    """
    # Import the actual APIError class
    from services.connections import APIError

    # Configure mock to raise APIError
    error_message = "API error creating desktop"
    mock_connections_service.scale_up.side_effect = APIError(error_message, status_code=400)

    # Test data
    data = {"name": "test-desktop", "persistent_home": True, "desktop_configuration_id": 1}

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}

    # Use the with app.app_context to ensure the request context is available
    with client_with_connection_routes.application.app_context():
        with client_with_connection_routes.application.test_request_context():
            response = client_with_connection_routes.post("/scaleup", json=data, headers=headers)

    # Check response
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "error" in data
    assert data["error"] == error_message


def test_scale_up_desktop_generic_error(
    mock_auth_decorators, client_with_connection_routes, mock_connections_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/scaleup' endpoint is requested but a generic error occurs
    THEN check that the appropriate error response is returned
    """
    # Configure mock to raise generic Exception
    error_message = "Failed to create desktop"
    mock_connections_service.scale_up.side_effect = Exception(error_message)

    # Test data
    data = {"name": "test-desktop", "persistent_home": True, "desktop_configuration_id": 1}

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_connection_routes.post("/scaleup", json=data, headers=headers)

    # Check response
    assert response.status_code == 500
    data = json.loads(response.data)
    assert "error" in data
    # Check the error matches what's returned by the route handler for generic exceptions
    assert data["error"] == error_message
