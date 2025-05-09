"""
This module contains unit tests for the desktop configurations client.
"""
import pytest
from unittest.mock import patch, MagicMock
from http import HTTPStatus

from clients.desktop_configurations import DesktopConfigurationsClient
from clients.base import APIError


@pytest.fixture
def desktop_config_client():
    """Fixture for desktop configurations client with mocked requests."""
    client = DesktopConfigurationsClient(base_url="http://test-api")
    return client


@patch("requests.request")
def test_list_configurations_success(mock_request, desktop_config_client):
    """
    GIVEN a desktop configurations client
    WHEN list_configurations is called
    THEN check that configurations are returned correctly
    """
    # Configure mock response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "configurations": [
            {"id": 1, "name": "Standard", "description": "Standard desktop"},
            {"id": 2, "name": "Performance", "description": "High-performance desktop"},
        ]
    }
    mock_request.return_value = mock_response

    # Call the method
    result = desktop_config_client.list_configurations()

    # Verify results
    assert len(result) == 2
    assert result[0]["name"] == "Standard"
    assert result[1]["name"] == "Performance"

    # Verify the request was made correctly
    mock_request.assert_called_once()
    args, kwargs = mock_request.call_args
    assert kwargs["method"] == "GET"
    assert kwargs["url"] == "http://test-api/api/desktop-config/list"


@patch("requests.request")
def test_list_configurations_error(mock_request, desktop_config_client):
    """
    GIVEN a desktop configurations client
    WHEN list_configurations is called and the API returns an error
    THEN check that an APIError is raised
    """
    # Configure mock response to simulate an error
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.json.return_value = {"error": "Internal server error"}
    mock_request.return_value = mock_response

    # Call the method and expect an exception
    with pytest.raises(APIError) as exc_info:
        desktop_config_client.list_configurations()

    # Verify the exception contains the error message
    assert "Internal server error" in str(exc_info.value)


@patch("requests.request")
def test_create_configuration_success(mock_request, desktop_config_client):
    """
    GIVEN a desktop configurations client
    WHEN create_configuration is called with valid data
    THEN check that the configuration is created correctly
    """
    # Configuration data to create
    config_data = {
        "name": "TestConfig",
        "description": "Test configuration",
        "image": "test-image:latest",
        "cpu": 2,
        "ram": "4G",
        "gpu": False,
    }

    # Configure mock response
    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.json.return_value = {
        "id": 3,
        "name": "TestConfig",
        "description": "Test configuration",
        "image": "test-image:latest",
    }
    mock_request.return_value = mock_response

    # Call the method
    result = desktop_config_client.create_configuration(config_data)

    # Verify results
    assert result["id"] == 3
    assert result["name"] == "TestConfig"

    # Verify the request was made correctly
    mock_request.assert_called_once()
    args, kwargs = mock_request.call_args
    assert kwargs["method"] == "POST"
    assert kwargs["url"] == "http://test-api/api/desktop-config/create"
    assert kwargs["json"] == config_data


@patch("requests.request")
def test_update_configuration_success(mock_request, desktop_config_client):
    """
    GIVEN a desktop configurations client
    WHEN update_configuration is called with valid data
    THEN check that the configuration is updated correctly
    """
    # Configuration data to update
    config_id = 1
    config_data = {"name": "UpdatedConfig", "description": "Updated configuration"}

    # Configure mock response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"id": config_id, "name": "UpdatedConfig", "description": "Updated configuration"}
    mock_request.return_value = mock_response

    # Call the method
    result = desktop_config_client.update_configuration(config_id, config_data)

    # Verify results
    assert result["id"] == config_id
    assert result["name"] == "UpdatedConfig"

    # Verify the request was made correctly
    mock_request.assert_called_once()
    args, kwargs = mock_request.call_args
    assert kwargs["method"] == "PUT"
    assert kwargs["url"] == f"http://test-api/api/desktop-config/update/{config_id}"
    assert kwargs["json"] == config_data


@patch("requests.request")
def test_get_configuration_success(mock_request, desktop_config_client):
    """
    GIVEN a desktop configurations client
    WHEN get_configuration is called with a valid ID
    THEN check that the configuration details are returned correctly
    """
    # Configuration ID to get
    config_id = 2

    # Configure mock response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "id": config_id,
        "name": "Performance",
        "description": "High-performance desktop",
        "image": "performance-image:latest",
    }
    mock_request.return_value = mock_response

    # Call the method
    result = desktop_config_client.get_configuration(config_id)

    # Verify results
    assert result["id"] == config_id
    assert result["name"] == "Performance"

    # Verify the request was made correctly
    mock_request.assert_called_once()
    args, kwargs = mock_request.call_args
    assert kwargs["method"] == "GET"
    assert kwargs["url"] == f"http://test-api/api/desktop-config/get/{config_id}"


@patch("requests.request")
def test_delete_configuration_success(mock_request, desktop_config_client):
    """
    GIVEN a desktop configurations client
    WHEN delete_configuration is called with a valid ID
    THEN check that the configuration is deleted correctly
    """
    # Configuration ID to delete
    config_id = 3

    # Configure mock response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"message": "Configuration deleted successfully"}
    mock_request.return_value = mock_response

    # Call the method
    result = desktop_config_client.delete_configuration(config_id)

    # Verify results
    assert "message" in result
    assert "deleted successfully" in result["message"]

    # Verify the request was made correctly
    mock_request.assert_called_once()
    args, kwargs = mock_request.call_args
    assert kwargs["method"] == "DELETE"
    assert kwargs["url"] == f"http://test-api/api/desktop-config/delete/{config_id}"


@patch("requests.request")
def test_get_users_success(mock_request, desktop_config_client):
    """
    GIVEN a desktop configurations client
    WHEN get_users is called
    THEN check that users are returned correctly
    """
    # Configure mock response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "users": [{"username": "user1", "is_admin": False}, {"username": "user2", "is_admin": True}]
    }
    mock_request.return_value = mock_response

    # Call the method
    result = desktop_config_client.get_users()

    # Verify results
    assert "data" in result
    assert len(result["data"]) == 2
    assert result["data"][0]["username"] == "user1"
    assert result["data"][1]["username"] == "user2"

    # Verify the request was made correctly
    mock_request.assert_called_once()
    args, kwargs = mock_request.call_args
    assert kwargs["method"] == "GET"
    assert kwargs["url"] == "http://test-api/api/users/list"


@patch("requests.request")
def test_get_configuration_users_success(mock_request, desktop_config_client):
    """
    GIVEN a desktop configurations client
    WHEN get_configuration_users is called
    THEN check that configuration users are returned correctly
    """
    # Configuration ID
    config_id = 1

    # Configure mock response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "users": [{"username": "user1", "access_level": "read"}, {"username": "user2", "access_level": "write"}]
    }
    mock_request.return_value = mock_response

    # Call the method
    result = desktop_config_client.get_configuration_users(config_id)

    # Verify results
    assert "data" in result
    assert len(result["data"]) == 2
    assert result["data"][0]["username"] == "user1"
    assert result["data"][1]["access_level"] == "write"

    # Verify the request was made correctly
    mock_request.assert_called_once()
    args, kwargs = mock_request.call_args
    assert kwargs["method"] == "GET"
    assert kwargs["url"] == f"http://test-api/api/desktop-config/access/{config_id}"


@patch("requests.request")
def test_get_connections_success(mock_request, desktop_config_client):
    """
    GIVEN a desktop configurations client
    WHEN get_connections is called
    THEN check that connections are returned correctly
    """
    # Configure mock response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "connections": [
            {"id": "conn1", "name": "Connection1", "desktop_configuration": {"id": 1}},
            {"id": "conn2", "name": "Connection2", "desktop_configuration": {"id": 2}},
        ]
    }
    mock_request.return_value = mock_response

    # Call the method
    result = desktop_config_client.get_connections()

    # Verify results
    assert "data" in result
    assert len(result["data"]) == 2
    assert result["data"][0]["name"] == "Connection1"
    assert result["data"][1]["desktop_configuration"]["id"] == 2

    # Verify the request was made correctly
    mock_request.assert_called_once()
    args, kwargs = mock_request.call_args
    assert kwargs["method"] == "GET"
    assert kwargs["url"] == "http://test-api/api/connections/list"


@patch("requests.request")
def test_error_handling_with_token(mock_request, desktop_config_client):
    """
    GIVEN a desktop configurations client
    WHEN a method is called with a token and an error occurs
    THEN check that the error is properly handled and the token is included in headers
    """
    # Configure mock response to simulate an error
    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_response.json.return_value = {"error": "Access denied"}
    mock_request.return_value = mock_response

    # Call the method with a token and expect an exception
    token = "test-token-123"
    with pytest.raises(APIError) as exc_info:
        desktop_config_client.list_configurations(token=token)

    # Verify the exception contains the error message
    assert mock_response.json()["error"] in str(exc_info.value)

    # Verify the token was included in the request
    mock_request.assert_called_once()
    args, kwargs = mock_request.call_args
    assert "headers" in kwargs
    assert "Authorization" in kwargs["headers"]
    assert kwargs["headers"]["Authorization"] == f"Bearer {token}"
