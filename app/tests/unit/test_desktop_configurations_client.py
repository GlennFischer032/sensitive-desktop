"""
Unit tests for the Desktop Configurations client.
"""

import pytest
from unittest.mock import patch

from app.clients.desktop_configurations import DesktopConfigurationsClient
from app.clients.base import APIError


def test_desktop_configurations_client_initialization():
    """
    GIVEN a DesktopConfigurationsClient class
    WHEN a new DesktopConfigurationsClient is created
    THEN check it initializes correctly
    """
    client = DesktopConfigurationsClient()
    assert client is not None


@patch("app.clients.base.BaseClient.get")
def test_list_configurations_success(mock_get):
    """
    GIVEN a DesktopConfigurationsClient
    WHEN list_configurations() is called
    THEN check it calls the API correctly and returns the response
    """
    # Set up mock
    mock_response = (
        {
            "configurations": [
                {"id": 1, "name": "Config1", "image": "img1", "cpu": 2, "ram": "4Gi"},
                {"id": 2, "name": "Config2", "image": "img2", "cpu": 4, "ram": "8Gi"},
            ]
        },
        200,
    )
    mock_get.return_value = mock_response

    # Call method
    client = DesktopConfigurationsClient()
    configs = client.list_configurations()

    # Verify
    mock_get.assert_called_once()
    assert len(configs) == 2
    assert configs[0]["name"] == "Config1"
    assert configs[1]["cpu"] == 4


@patch("app.clients.base.BaseClient.get")
def test_list_configurations_error(mock_get):
    """
    GIVEN a DesktopConfigurationsClient
    WHEN list_configurations() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_get.side_effect = APIError("Failed to fetch configurations", 500)

    # Call method and verify exception
    client = DesktopConfigurationsClient()
    with pytest.raises(APIError):
        client.list_configurations()


@patch("app.clients.base.BaseClient.post")
def test_create_configuration_success(mock_post):
    """
    GIVEN a DesktopConfigurationsClient
    WHEN create_configuration() is called
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = (
        {
            "id": 3,
            "name": "New Config",
            "description": "Test Config",
            "image": "test-image",
            "cpu": 2,
            "ram": "4Gi",
        },
        201,
    )
    mock_post.return_value = mock_response

    # Call method
    client = DesktopConfigurationsClient()
    config_data = {
        "name": "New Config",
        "description": "Test Config",
        "image": "test-image",
        "cpu": 2,
        "ram": "4Gi",
    }
    result = client.create_configuration(config_data=config_data)

    # Verify
    mock_post.assert_called_once()
    assert result["name"] == "New Config"
    assert result["image"] == "test-image"
    assert result["cpu"] == 2


@patch("app.clients.base.BaseClient.post")
def test_create_configuration_error(mock_post):
    """
    GIVEN a DesktopConfigurationsClient
    WHEN create_configuration() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_post.side_effect = APIError("Failed to create configuration", 400)

    # Call method and verify exception
    client = DesktopConfigurationsClient()
    config_data = {"name": "Invalid Config"}
    with pytest.raises(APIError):
        client.create_configuration(config_data=config_data)


@patch("app.clients.base.BaseClient.put")
def test_update_configuration_success(mock_put):
    """
    GIVEN a DesktopConfigurationsClient
    WHEN update_configuration() is called
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = (
        {
            "id": 1,
            "name": "Updated Config",
            "description": "Updated Test Config",
            "image": "updated-image",
            "cpu": 4,
            "ram": "8Gi",
        },
        200,
    )
    mock_put.return_value = mock_response

    # Call method
    client = DesktopConfigurationsClient()
    config_data = {
        "name": "Updated Config",
        "description": "Updated Test Config",
        "image": "updated-image",
        "cpu": 4,
        "ram": "8Gi",
    }
    result = client.update_configuration(config_id=1, config_data=config_data)

    # Verify
    mock_put.assert_called_once()
    assert result["name"] == "Updated Config"
    assert result["cpu"] == 4
    assert result["ram"] == "8Gi"


@patch("app.clients.base.BaseClient.put")
def test_update_configuration_error(mock_put):
    """
    GIVEN a DesktopConfigurationsClient
    WHEN update_configuration() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_put.side_effect = APIError("Configuration not found", 404)

    # Call method and verify exception
    client = DesktopConfigurationsClient()
    config_data = {"name": "Updated Config"}
    with pytest.raises(APIError):
        client.update_configuration(config_id=999, config_data=config_data)


@patch("app.clients.base.BaseClient.get")
def test_get_configuration_success(mock_get):
    """
    GIVEN a DesktopConfigurationsClient
    WHEN get_configuration() is called
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = (
        {
            "id": 1,
            "name": "Config1",
            "description": "Test Config",
            "image": "img1",
            "cpu": 2,
            "ram": "4Gi",
            "created_at": "2023-01-01T00:00:00Z",
            "is_public": True,
        },
        200,
    )
    mock_get.return_value = mock_response

    # Call method
    client = DesktopConfigurationsClient()
    config = client.get_configuration(config_id=1)

    # Verify
    mock_get.assert_called_once()
    assert config["id"] == 1
    assert config["name"] == "Config1"
    assert config["is_public"] is True


@patch("app.clients.base.BaseClient.get")
def test_get_configuration_error(mock_get):
    """
    GIVEN a DesktopConfigurationsClient
    WHEN get_configuration() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_get.side_effect = APIError("Configuration not found", 404)

    # Call method and verify exception
    client = DesktopConfigurationsClient()
    with pytest.raises(APIError):
        client.get_configuration(config_id=999)


@patch("app.clients.base.BaseClient.delete")
def test_delete_configuration_success(mock_delete):
    """
    GIVEN a DesktopConfigurationsClient
    WHEN delete_configuration() is called
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = ({"status": "Configuration deleted successfully"}, 200)
    mock_delete.return_value = mock_response

    # Call method
    client = DesktopConfigurationsClient()
    result = client.delete_configuration(config_id=1)

    # Verify
    mock_delete.assert_called_once()
    assert result["status"] == "Configuration deleted successfully"


@patch("app.clients.base.BaseClient.delete")
def test_delete_configuration_error(mock_delete):
    """
    GIVEN a DesktopConfigurationsClient
    WHEN delete_configuration() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_delete.side_effect = APIError("Configuration not found", 404)

    # Call method and verify exception
    client = DesktopConfigurationsClient()
    with pytest.raises(APIError):
        client.delete_configuration(config_id=999)


@patch("app.clients.base.BaseClient.get")
def test_get_users_success(mock_get):
    """
    GIVEN a DesktopConfigurationsClient
    WHEN get_users() is called
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = (
        {
            "users": [
                {"id": "user1", "username": "johndoe", "is_admin": False},
                {"id": "user2", "username": "janedoe", "is_admin": True},
            ]
        },
        200,
    )
    mock_get.return_value = mock_response

    # Call method
    client = DesktopConfigurationsClient()
    result = client.get_users()

    # Verify
    mock_get.assert_called_once()
    assert len(result["data"]) == 2
    assert result["data"][0]["username"] == "johndoe"
    assert result["data"][1]["is_admin"] is True


@patch("app.clients.base.BaseClient.get")
def test_get_users_error(mock_get):
    """
    GIVEN a DesktopConfigurationsClient
    WHEN get_users() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_get.side_effect = APIError("Failed to fetch users", 500)

    # Call method and verify exception
    client = DesktopConfigurationsClient()
    with pytest.raises(APIError):
        client.get_users()


@patch("app.clients.base.BaseClient.get")
def test_get_configuration_users_success(mock_get):
    """
    GIVEN a DesktopConfigurationsClient
    WHEN get_configuration_users() is called
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = (
        {
            "users": [
                {"id": "user1", "username": "johndoe", "access_type": "read"},
                {"id": "user2", "username": "janedoe", "access_type": "write"},
            ]
        },
        200,
    )
    mock_get.return_value = mock_response

    # Call method
    client = DesktopConfigurationsClient()
    result = client.get_configuration_users(config_id=1)

    # Verify
    mock_get.assert_called_once()
    assert len(result["data"]) == 2
    assert result["data"][0]["username"] == "johndoe"
    assert result["data"][1]["access_type"] == "write"


@patch("app.clients.base.BaseClient.get")
def test_get_configuration_users_error(mock_get):
    """
    GIVEN a DesktopConfigurationsClient
    WHEN get_configuration_users() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_get.side_effect = APIError("Failed to fetch configuration users", 404)

    # Call method and verify exception
    client = DesktopConfigurationsClient()
    with pytest.raises(APIError):
        client.get_configuration_users(config_id=999)


@patch("app.clients.base.BaseClient.get")
def test_get_connections_success(mock_get):
    """
    GIVEN a DesktopConfigurationsClient
    WHEN get_connections() is called
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = (
        {
            "connections": [
                {"id": "conn1", "name": "connection1", "config_id": 1, "status": "running"},
                {"id": "conn2", "name": "connection2", "config_id": 2, "status": "stopped"},
            ]
        },
        200,
    )
    mock_get.return_value = mock_response

    # Call method
    client = DesktopConfigurationsClient()
    result = client.get_connections()

    # Verify
    mock_get.assert_called_once()
    assert len(result["data"]) == 2
    assert result["data"][0]["name"] == "connection1"
    assert result["data"][1]["config_id"] == 2


@patch("app.clients.base.BaseClient.get")
def test_get_connections_error(mock_get):
    """
    GIVEN a DesktopConfigurationsClient
    WHEN get_connections() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_get.side_effect = APIError("Failed to fetch connections", 500)

    # Call method and verify exception
    client = DesktopConfigurationsClient()
    with pytest.raises(APIError):
        client.get_connections()
