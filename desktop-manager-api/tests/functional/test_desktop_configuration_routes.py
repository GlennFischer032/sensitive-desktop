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
def mock_desktop_config_service():
    """Mock the DesktopConfigurationService for testing."""
    with patch("routes.desktop_configuration_routes.DesktopConfigurationService") as mock:
        # Setup mock methods with appropriate return values
        mock_instance = MagicMock()

        # Mock create_configuration
        mock_instance.create_configuration.return_value = {
            "id": 1,
            "name": "test-desktop-config",
            "cpu": "2",
            "memory": "4Gi",
            "created_by": "admin",
            "created_at": datetime.utcnow().isoformat(),
        }

        # Mock list_configurations
        mock_instance.list_configurations.return_value = {
            "configurations": [
                {
                    "id": 1,
                    "name": "test-config-1",
                    "cpu": "2",
                    "memory": "4Gi",
                    "created_by": "admin",
                    "created_at": datetime.utcnow().isoformat(),
                },
                {
                    "id": 2,
                    "name": "test-config-2",
                    "cpu": "4",
                    "memory": "8Gi",
                    "created_by": "admin",
                    "created_at": datetime.utcnow().isoformat(),
                },
            ]
        }

        # Mock get_configuration
        mock_instance.get_configuration.return_value = {
            "id": 1,
            "name": "test-desktop-config",
            "cpu": "2",
            "memory": "4Gi",
            "created_by": "admin",
            "created_at": datetime.utcnow().isoformat(),
        }

        # Mock update_configuration
        mock_instance.update_configuration.return_value = {
            "id": 1,
            "name": "updated-config",
            "cpu": "4",
            "memory": "8Gi",
            "created_by": "admin",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
        }

        # Mock delete_configuration
        mock_instance.delete_configuration.return_value = {"message": "Desktop configuration deleted successfully"}

        # Mock get_configuration_access connections
        mock_instance.get_configuration_access.return_value = {
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
    with patch("routes.desktop_configuration_routes.token_required", dummy_decorator), patch(
        "routes.desktop_configuration_routes.admin_required", dummy_decorator
    ), patch("routes.desktop_configuration_routes.with_db_session", dummy_decorator):
        yield


# Create a fake user and db_session to use in requests
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
def mock_token():
    """Mock token for authorization."""
    return "fake-test-token"


@pytest.fixture
def app_with_desktop_config_routes(test_app, mock_user_repository, mock_token_repository):
    """
    Register desktop_configuration blueprint with test app.
    """
    from routes.desktop_configuration_routes import desktop_config_bp
    import jwt

    # Register the blueprint with a unique name to avoid conflicts
    test_app.register_blueprint(desktop_config_bp, name="desktop_config_bp_test")

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
                    with patch("routes.desktop_configuration_routes.token_required", lambda f: f):
                        # Mock the admin_required decorator to skip permission check
                        with patch("routes.desktop_configuration_routes.admin_required", lambda f: f):
                            # Mock the with_db_session decorator
                            with patch("routes.desktop_configuration_routes.with_db_session", lambda f: f):
                                yield test_app


@pytest.fixture
def client_with_desktop_config_routes(app_with_desktop_config_routes):
    """Get a test client with the desktop_configuration routes registered."""
    return app_with_desktop_config_routes.test_client()


def test_create_desktop_configuration(
    mock_auth_decorators, client_with_desktop_config_routes, mock_desktop_config_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/create' endpoint is requested (POST) with valid data
    THEN check that the response is valid and desktop configuration is created
    """
    # Test data
    config_data = {"name": "test-desktop-config", "cpu": "2", "memory": "4Gi", "description": "Test configuration"}

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_desktop_config_routes.post("/create", json=config_data, headers=headers)

    # Check response
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data["id"] == 1
    assert data["name"] == "test-desktop-config"
    assert data["cpu"] == "2"
    assert data["memory"] == "4Gi"

    # Verify mock was called correctly
    mock_desktop_config_service.create_configuration.assert_called_once()


def test_list_desktop_configurations(
    mock_auth_decorators, client_with_desktop_config_routes, mock_desktop_config_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/list' endpoint is requested (GET)
    THEN check that the response contains a list of desktop configurations
    """
    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_desktop_config_routes.get("/list", headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "configurations" in data
    assert len(data["configurations"]) == 2
    assert data["configurations"][0]["name"] == "test-config-1"
    assert data["configurations"][1]["name"] == "test-config-2"

    # Verify mock was called correctly
    mock_desktop_config_service.list_configurations.assert_called_once()


def test_get_desktop_configuration(
    mock_auth_decorators, client_with_desktop_config_routes, mock_desktop_config_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/get/{id}' endpoint is requested (GET)
    THEN check that the configuration details are returned
    """
    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_desktop_config_routes.get("/get/1", headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["id"] == 1
    assert data["name"] == "test-desktop-config"
    assert data["cpu"] == "2"
    assert data["memory"] == "4Gi"

    # Verify mock was called correctly
    mock_desktop_config_service.get_configuration.assert_called_once()


def test_update_desktop_configuration(
    mock_auth_decorators, client_with_desktop_config_routes, mock_desktop_config_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/update/{id}' endpoint is requested (PUT) with valid data
    THEN check that the configuration is updated
    """
    # Test data
    config_data = {"name": "updated-config", "cpu": "4", "memory": "8Gi"}

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_desktop_config_routes.put("/update/1", json=config_data, headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["id"] == 1
    assert data["name"] == "updated-config"
    assert data["cpu"] == "4"
    assert data["memory"] == "8Gi"

    # Verify mock was called correctly
    mock_desktop_config_service.update_configuration.assert_called_once()


def test_delete_desktop_configuration(
    mock_auth_decorators, client_with_desktop_config_routes, mock_desktop_config_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/delete/{id}' endpoint is requested (DELETE)
    THEN check that the configuration is deleted successfully
    """
    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_desktop_config_routes.delete("/delete/1", headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "message" in data
    assert data["message"] == "Desktop configuration deleted successfully"

    # Verify mock was called correctly
    mock_desktop_config_service.delete_configuration.assert_called_once()


def test_get_desktop_configuration_access(
    mock_auth_decorators, client_with_desktop_config_routes, mock_desktop_config_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/access/{id}' endpoint is requested (GET)
    THEN check that the access information is returned
    """
    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_desktop_config_routes.get("/access/1", headers=headers)

    # Check response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "connections" in data
    assert len(data["connections"]) == 1
    assert data["connections"][0]["type"] == "desktop"
    assert data["connections"][0]["name"] == "desktop-1"

    # Verify mock was called correctly
    mock_desktop_config_service.get_configuration_access.assert_called_once()


def test_create_desktop_configuration_api_error(
    mock_auth_decorators, client_with_desktop_config_routes, mock_desktop_config_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/create' endpoint is requested but an APIError occurs
    THEN check that the appropriate error response is returned
    """
    # Configure mock to raise APIError
    from services.connections import APIError

    error_message = "API error creating configuration"
    mock_desktop_config_service.create_configuration.side_effect = APIError(error_message, status_code=400)

    # Test data
    config_data = {"name": "test-desktop-config", "cpu": "2", "memory": "4Gi"}

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_desktop_config_routes.post("/create", json=config_data, headers=headers)

    # Check response
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "error" in data
    assert data["error"] == error_message


def test_create_desktop_configuration_generic_error(
    mock_auth_decorators, client_with_desktop_config_routes, mock_desktop_config_service, mock_token
):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/create' endpoint is requested but a generic error occurs
    THEN check that the appropriate error response is returned
    """
    # Configure mock to raise generic Exception
    error_message = "Failed to create desktop configuration"
    mock_desktop_config_service.create_configuration.side_effect = Exception(error_message)

    # Test data
    config_data = {"name": "test-desktop-config", "cpu": "2", "memory": "4Gi"}

    # Make request with auth header
    headers = {"Authorization": f"Bearer {mock_token}"}
    response = client_with_desktop_config_routes.post("/create", json=config_data, headers=headers)

    # Check response
    assert response.status_code == 500
    data = json.loads(response.data)
    assert "error" in data
    assert "details" in data
    assert error_message == data["details"]
