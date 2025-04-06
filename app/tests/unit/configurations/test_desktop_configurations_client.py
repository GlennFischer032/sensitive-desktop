from unittest.mock import MagicMock, patch

import pytest
from flask import current_app, session

from app.clients.base import APIError
from app.clients.desktop_configurations import DesktopConfigurationsClient
from app.tests.conftest import TEST_TOKEN


@pytest.fixture
def mock_api_response():
    """Mock API response."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "success"}
    return mock_response


@pytest.fixture
def config_client(app):
    """Get desktop configurations client."""
    with app.app_context():
        with patch("requests.request") as mock_request:
            client = DesktopConfigurationsClient()
            yield client, mock_request


def test_list_configurations(config_client, app, mock_api_response):
    """Test listing desktop configurations."""
    client, mock_request = config_client
    mock_request.return_value = mock_api_response
    mock_response = mock_api_response
    mock_response.json.return_value = {
        "status": "success",
        "configurations": [{"id": 1, "name": "Test Config"}],
    }

    # Use patch to simulate session with token
    with app.test_request_context():
        with patch.dict(session, {"token": TEST_TOKEN}):
            result = client.list_configurations()

    mock_request.assert_called_once()
    expected_url = f"{current_app.config['API_URL']}/api/desktop-config/list"
    assert mock_request.call_args[1]["url"] == expected_url
    assert result == [{"id": 1, "name": "Test Config"}]


def test_list_configurations_no_token(config_client):
    """Test list_configurations with no token."""
    client, _ = config_client

    # Empty session with no token
    with patch("flask.session", {}):
        with pytest.raises(APIError) as excinfo:
            client.list_configurations()

        assert "Authentication required" in str(excinfo.value)
        assert excinfo.value.status_code == 401


def test_list_configurations_api_error(config_client, app, mock_api_response):
    """Test handling API error when listing configurations."""
    client, mock_request = config_client

    # Mock error response
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.json.return_value = {"error": "Internal server error"}
    mock_response.text = '{"error": "Internal server error"}'
    mock_request.return_value = mock_response

    # Use patch to simulate session with token
    with app.test_request_context():
        with patch.dict(session, {"token": TEST_TOKEN}):
            with pytest.raises(APIError) as excinfo:
                client.list_configurations()

    assert excinfo.value.status_code == 500
    assert "Internal server error" in str(excinfo.value)
    mock_request.assert_called_once()
    expected_url = f"{current_app.config['API_URL']}/api/desktop-config/list"
    assert mock_request.call_args[1]["url"] == expected_url


def test_create_configuration(config_client, app, mock_api_response):
    """Test creating desktop configuration."""
    client, mock_request = config_client
    mock_request.return_value = mock_api_response
    mock_response = mock_api_response
    mock_response.json.return_value = {
        "status": "success",
        "config": {"id": 1, "name": "Test Config"},
    }

    config_data = {"name": "Test Config", "cpu": 2, "ram": 4096}

    # Use patch to simulate session with token
    with app.test_request_context():
        with patch.dict(session, {"token": TEST_TOKEN}):
            client.create_configuration(config_data)

    mock_request.assert_called_once()
    expected_url = f"{current_app.config['API_URL']}/api/desktop-config/create"
    assert mock_request.call_args[1]["url"] == expected_url
    assert mock_request.call_args[1]["json"] == config_data


def test_create_configuration_validation_error(config_client, app, mock_api_response):
    """Test creating a configuration with invalid data."""
    client, mock_request = config_client

    # Mock error response
    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.json.return_value = {
        "error": "Validation error",
        "details": {"name": ["Name is required"]},
    }
    mock_response.text = '{"error": "Validation error"}'
    mock_request.return_value = mock_response

    config_data = {"cpu": 2, "ram": 4096}  # Missing name

    # Use patch to simulate session with token
    with app.test_request_context():
        with patch.dict(session, {"token": TEST_TOKEN}):
            with pytest.raises(APIError) as excinfo:
                client.create_configuration(config_data)

    assert excinfo.value.status_code == 400
    assert "Validation error" in str(excinfo.value)
    mock_request.assert_called_once()
    expected_url = f"{current_app.config['API_URL']}/api/desktop-config/create"
    assert mock_request.call_args[1]["url"] == expected_url
    assert mock_request.call_args[1]["json"] == config_data


def test_update_configuration_success(config_client, app, mock_api_response):
    """Test updating desktop configuration."""
    client, mock_request = config_client
    mock_request.return_value = mock_api_response
    mock_response = mock_api_response
    mock_response.json.return_value = {
        "status": "success",
        "config": {"id": 1, "name": "Updated Config"},
    }

    config_data = {"name": "Updated Config", "cpu": 4, "ram": 8192}
    config_id = 1

    # Use patch to simulate session with token
    with app.test_request_context():
        with patch.dict(session, {"token": TEST_TOKEN}):
            client.update_configuration(config_id, config_data)

    mock_request.assert_called_once()
    expected_url = f"{current_app.config['API_URL']}/api/desktop-config/update/{config_id}"
    assert mock_request.call_args[1]["url"] == expected_url
    assert mock_request.call_args[1]["json"] == config_data


def test_get_configuration_success(config_client, app, mock_api_response):
    """Test getting desktop configuration."""
    client, mock_request = config_client
    mock_request.return_value = mock_api_response
    mock_response = mock_api_response
    mock_response.json.return_value = {
        "status": "success",
        "config": {"id": 1, "name": "Test Config"},
    }

    config_id = 1

    # Use patch to simulate session with token
    with app.test_request_context():
        with patch.dict(session, {"token": TEST_TOKEN}):
            client.get_configuration(config_id)

    mock_request.assert_called_once()
    expected_url = f"{current_app.config['API_URL']}/api/desktop-config/get/{config_id}"
    assert mock_request.call_args[1]["url"] == expected_url


def test_get_configuration_not_found(config_client, app):
    """Test getting a configuration that doesn't exist."""
    client, mock_request = config_client

    # Mock error response
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.json.return_value = {
        "error": "Configuration not found",
        "details": {"message": "No configuration with id 999 exists"},
    }
    mock_response.text = '{"error": "Configuration not found"}'
    mock_request.return_value = mock_response

    config_id = 999

    # Use patch to simulate session with token
    with app.test_request_context():
        with patch.dict(session, {"token": TEST_TOKEN}):
            with pytest.raises(APIError) as excinfo:
                client.get_configuration(config_id)

    assert excinfo.value.status_code == 404
    assert "Configuration not found" in str(excinfo.value)
    mock_request.assert_called_once()
    expected_url = f"{current_app.config['API_URL']}/api/desktop-config/get/{config_id}"
    assert mock_request.call_args[1]["url"] == expected_url


def test_delete_configuration_success(config_client, app, mock_api_response):
    """Test deleting desktop configuration."""
    client, mock_request = config_client
    mock_request.return_value = mock_api_response
    mock_response = mock_api_response
    mock_response.json.return_value = {
        "status": "success",
        "message": "Configuration deleted successfully",
    }

    config_id = 1

    # Use patch to simulate session with token
    with app.test_request_context():
        with patch.dict(session, {"token": TEST_TOKEN}):
            result = client.delete_configuration(config_id)

    mock_request.assert_called_once()
    expected_url = f"{current_app.config['API_URL']}/api/desktop-config/delete/{config_id}"
    assert mock_request.call_args[1]["url"] == expected_url
    assert result["status"] == "success"


def test_delete_configuration_in_use(config_client, app, mock_api_response):
    """Test deleting a configuration that's in use by connections."""
    client, mock_request = config_client

    # Mock error response
    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.json.return_value = {
        "error": "Configuration is in use",
        "details": {"message": "Configuration is in use by active connections"},
    }
    mock_response.text = '{"error": "Configuration is in use"}'
    mock_request.return_value = mock_response

    config_id = 1

    # Use patch to simulate session with token
    with app.test_request_context():
        with patch.dict(session, {"token": TEST_TOKEN}):
            with pytest.raises(APIError) as excinfo:
                client.delete_configuration(config_id)

    assert excinfo.value.status_code == 400
    assert "Configuration is in use" in str(excinfo.value)
    mock_request.assert_called_once()
    expected_url = f"{current_app.config['API_URL']}/api/desktop-config/delete/{config_id}"
    assert mock_request.call_args[1]["url"] == expected_url


def test_get_users_success(config_client, app, mock_api_response):
    """Test getting users list."""
    client, mock_request = config_client
    mock_request.return_value = mock_api_response
    mock_response = mock_api_response
    mock_response.json.return_value = {
        "status": "success",
        "users": [
            {"id": 1, "username": "testuser", "is_admin": False},
            {"id": 2, "username": "admin", "is_admin": True},
        ],
    }

    # Use patch to simulate session with token
    with app.test_request_context():
        with patch.dict(session, {"token": TEST_TOKEN}):
            result = client.get_users()

    mock_request.assert_called_once()
    expected_url = f"{current_app.config['API_URL']}/api/users/list"
    assert mock_request.call_args[1]["url"] == expected_url
    assert len(result["data"]) == 2
    assert result["data"][0]["username"] == "testuser"
    assert result["data"][1]["username"] == "admin"


def test_get_configuration_users_success(config_client, app, mock_api_response):
    """Test getting users with access to a configuration."""
    client, mock_request = config_client
    mock_request.return_value = mock_api_response
    mock_response = mock_api_response
    mock_response.json.return_value = {
        "status": "success",
        "users": [
            {"id": 1, "username": "testuser", "is_admin": False},
        ],
    }

    config_id = 1

    # Use patch to simulate session with token
    with app.test_request_context():
        with patch.dict(session, {"token": TEST_TOKEN}):
            result = client.get_configuration_users(config_id)

    mock_request.assert_called_once()
    expected_url = f"{current_app.config['API_URL']}/api/desktop-config/access/{config_id}"
    assert mock_request.call_args[1]["url"] == expected_url
    assert len(result["data"]) == 1
    assert result["data"][0]["username"] == "testuser"


def test_get_connections_success(config_client, app, mock_api_response):
    """Test getting connections list."""
    client, mock_request = config_client
    mock_request.return_value = mock_api_response
    mock_response = mock_api_response
    mock_response.json.return_value = {
        "status": "success",
        "connections": [
            {"id": 1, "name": "Connection 1", "config_id": 1},
            {"id": 2, "name": "Connection 2", "config_id": 2},
        ],
    }

    # Use patch to simulate session with token
    with app.test_request_context():
        with patch.dict(session, {"token": TEST_TOKEN}):
            result = client.get_connections()

    mock_request.assert_called_once()
    expected_url = f"{current_app.config['API_URL']}/api/connections/list"
    assert mock_request.call_args[1]["url"] == expected_url
    assert len(result["data"]) == 2
    assert result["data"][0]["name"] == "Connection 1"
    assert result["data"][1]["name"] == "Connection 2"
