import pytest
import sys
import os
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from flask.testing import FlaskClient
from flask import request, Flask
import jwt

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))


@pytest.fixture
def mock_storage_pvc_service():
    """Mock the StoragePVCService for testing."""
    with patch("routes.storage_pvc_routes.StoragePVCService") as mock:
        # Setup mock methods with appropriate return values
        mock_instance = MagicMock()

        # Mock create_storage_pvc
        mock_instance.create_storage_pvc.return_value = {
            "id": 1,
            "name": "test-pvc",
            "size": "10Gi",
            "status": "Creating",
            "created_by": "admin",
        }

        # Mock list_storage_pvcs
        mock_instance.list_storage_pvcs.return_value = {
            "pvcs": [
                {
                    "id": 1,
                    "name": "test-pvc-1",
                    "size": "10Gi",
                    "status": "Bound",
                    "created_at": datetime.utcnow().isoformat(),
                    "created_by": "admin",
                    "is_public": True,
                },
                {
                    "id": 2,
                    "name": "test-pvc-2",
                    "size": "20Gi",
                    "status": "Bound",
                    "created_at": datetime.utcnow().isoformat(),
                    "created_by": "admin",
                    "is_public": False,
                },
            ]
        }

        # Mock delete_storage_pvc
        mock_instance.delete_storage_pvc.return_value = {"message": "PVC deleted successfully"}

        # Mock get_pvc_access
        mock_instance.get_pvc_access.return_value = {"is_public": True, "allowed_users": ["user1", "user2"]}

        # Mock update_pvc_access
        mock_instance.update_pvc_access.return_value = {
            "message": "Access settings updated successfully",
            "is_public": False,
            "allowed_users": ["user3", "user4"],
        }

        # Mock get_storage_pvc_by_id
        mock_instance.get_storage_pvc_by_id.return_value = {
            "id": 1,
            "name": "test-pvc",
            "size": "10Gi",
            "status": "Bound",
            "created_at": datetime.utcnow().isoformat(),
            "created_by": "admin",
            "is_public": True,
        }

        # Mock get_pvc_connections
        mock_instance.get_pvc_connections.return_value = {
            "connections": [{"id": 1, "type": "desktop", "name": "desktop-1", "owner": "admin"}]
        }

        # Return the mock instance
        mock.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_auth_decorators():
    """Mock all auth decorators and DB session."""

    # Create simple pass-through decorators
    def dummy_decorator(f):
        return f

    # Apply mocks
    with patch("routes.storage_pvc_routes.token_required", dummy_decorator), patch(
        "routes.storage_pvc_routes.admin_required", dummy_decorator
    ), patch("routes.storage_pvc_routes.with_db_session", dummy_decorator):
        yield


# Create a fake user and db_session to use in requests
class FakeUser:
    def __init__(self):
        self.username = "admin"
        self.is_admin = True
        self.email = "admin@example.com"


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
def app_with_storage_pvc_routes(test_app, mock_user_repository, mock_token_repository):
    """
    Register storage_pvc blueprint with test app.
    """
    from routes.storage_pvc_routes import storage_pvc_bp

    # Register the blueprint with a unique name to avoid conflicts
    test_app.register_blueprint(storage_pvc_bp, name="storage_pvc_bp_test")

    # Create and register a before_request handler
    @test_app.before_request
    def set_test_user():
        # Mock the request.current_user and request.db_session
        if not hasattr(request, "current_user"):
            request.current_user = FakeUser()
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

                    # Mock the token_required decorator to pass through
                    with patch("routes.storage_pvc_routes.token_required", lambda f: f):
                        # Mock the admin_required decorator to skip permission check
                        with patch("routes.storage_pvc_routes.admin_required", lambda f: f):
                            # Mock the with_db_session decorator
                            with patch("routes.storage_pvc_routes.with_db_session", lambda f: f):
                                yield test_app


@pytest.fixture
def client_with_storage_pvc_routes(app_with_storage_pvc_routes):
    """Get a test client with the storage_pvc routes registered."""
    return app_with_storage_pvc_routes.test_client()


def test_create_storage_pvc(mock_auth_decorators, client_with_storage_pvc_routes, mock_storage_pvc_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/create' endpoint is requested (POST) with valid data
    THEN check that the response is valid and PVC is created
    """
    # Test data
    pvc_data = {"name": "test-pvc", "size": "10Gi", "is_public": True, "allowed_users": ["user1", "user2"]}

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_storage_pvc_routes.post("/create", json=pvc_data, headers=headers)

    # Check response
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data["id"] == 1
    assert data["name"] == "test-pvc"
    assert data["size"] == "10Gi"

    # Verify mock was called correctly
    mock_storage_pvc_service.create_storage_pvc.assert_called_once()


def test_list_storage_pvcs(mock_auth_decorators, client_with_storage_pvc_routes, mock_storage_pvc_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/list' endpoint is requested (GET)
    THEN check that the response contains a list of PVCs
    """
    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_storage_pvc_routes.get("/list", headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "pvcs" in data
    assert len(data["pvcs"]) == 2
    assert data["pvcs"][0]["name"] == "test-pvc-1"
    assert data["pvcs"][1]["name"] == "test-pvc-2"

    # Verify mock was called correctly
    mock_storage_pvc_service.list_storage_pvcs.assert_called_once()


def test_delete_storage_pvc(mock_auth_decorators, client_with_storage_pvc_routes, mock_storage_pvc_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/{pvc_id}' endpoint is requested (DELETE)
    THEN check that the PVC is deleted successfully
    """
    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_storage_pvc_routes.delete("/1", headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "message" in data
    assert data["message"] == "PVC deleted successfully"

    # Verify mock was called correctly
    mock_storage_pvc_service.delete_storage_pvc.assert_called_once()
    args, _ = mock_storage_pvc_service.delete_storage_pvc.call_args
    assert args[0] == 1  # Check that the first argument is the ID


def test_get_pvc_access(mock_auth_decorators, client_with_storage_pvc_routes, mock_storage_pvc_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/{pvc_id}/access' endpoint is requested (GET)
    THEN check that the access information is returned
    """
    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_storage_pvc_routes.get("/1/access", headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "is_public" in data
    assert data["is_public"] is True
    assert "allowed_users" in data
    assert len(data["allowed_users"]) == 2

    # Verify mock was called correctly
    mock_storage_pvc_service.get_pvc_access.assert_called_once()
    args, _ = mock_storage_pvc_service.get_pvc_access.call_args
    assert args[0] == 1  # Check that the first argument is the ID


def test_update_pvc_access(mock_auth_decorators, client_with_storage_pvc_routes, mock_storage_pvc_service, mock_token):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/{pvc_id}/access' endpoint is requested (POST)
    THEN check that the access settings are updated
    """
    # Test data
    access_data = {"is_public": False, "allowed_users": ["user3", "user4"]}

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_storage_pvc_routes.post("/1/access", json=access_data, headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "message" in data
    assert data["is_public"] is False
    assert "allowed_users" in data
    assert len(data["allowed_users"]) == 2

    # Verify mock was called correctly
    mock_storage_pvc_service.update_pvc_access.assert_called_once()


def test_get_storage_pvc_by_id(
    mock_auth_decorators, client_with_storage_pvc_routes, mock_storage_pvc_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/{pvc_id}' endpoint is requested (GET)
    THEN check that the PVC details are returned
    """
    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_storage_pvc_routes.get("/1", headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["id"] == 1
    assert data["name"] == "test-pvc"
    assert data["size"] == "10Gi"

    # Verify mock was called correctly
    mock_storage_pvc_service.get_storage_pvc_by_id.assert_called_once()
    args, _ = mock_storage_pvc_service.get_storage_pvc_by_id.call_args
    assert args[0] == 1  # Check that the first argument is the ID


def test_get_pvc_connections(
    mock_auth_decorators, client_with_storage_pvc_routes, mock_storage_pvc_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/connections/{pvc_id}' endpoint is requested (GET)
    THEN check that the connections using the PVC are returned
    """
    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_storage_pvc_routes.get("/connections/1", headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "connections" in data
    assert len(data["connections"]) == 1
    assert data["connections"][0]["type"] == "desktop"

    # Verify mock was called correctly
    mock_storage_pvc_service.get_pvc_connections.assert_called_once()
    args, _ = mock_storage_pvc_service.get_pvc_connections.call_args
    assert args[0] == 1  # Check that the first argument is the ID


def test_create_storage_pvc_api_error(
    mock_auth_decorators, client_with_storage_pvc_routes, mock_storage_pvc_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/create' endpoint is requested but an APIError occurs
    THEN check that the appropriate error response is returned
    """
    # Configure mock to raise APIError
    from services.connections import APIError

    error_message = "API error creating PVC"
    mock_storage_pvc_service.create_storage_pvc.side_effect = APIError(error_message, status_code=400)

    # Test data
    pvc_data = {"name": "test-pvc", "size": "10Gi"}

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_storage_pvc_routes.post("/create", json=pvc_data, headers=headers)

    # Check response
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "error" in data
    assert data["error"] == error_message


def test_create_storage_pvc_generic_error(
    mock_auth_decorators, client_with_storage_pvc_routes, mock_storage_pvc_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/create' endpoint is requested but a generic error occurs
    THEN check that the appropriate error response is returned
    """
    # Configure mock to raise generic Exception
    error_message = "Failed to create PVC"
    mock_storage_pvc_service.create_storage_pvc.side_effect = Exception(error_message)

    # Test data
    pvc_data = {"name": "test-pvc", "size": "10Gi"}

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_storage_pvc_routes.post("/create", json=pvc_data, headers=headers)

    # Check response
    assert response.status_code == 500
    data = json.loads(response.data)
    assert "error" in data
    assert error_message in data["error"]
