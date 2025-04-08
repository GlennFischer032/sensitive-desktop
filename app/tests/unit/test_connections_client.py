"""
Unit tests for the Connections client.
"""

import pytest
from unittest.mock import patch

from app.clients.connections import ConnectionsClient
from app.clients.base import APIError


def test_connections_client_initialization():
    """
    GIVEN a ConnectionsClient class
    WHEN a new ConnectionsClient is created
    THEN check it initializes correctly
    """
    client = ConnectionsClient()
    assert client is not None


@patch("app.clients.base.BaseClient.get")
def test_list_connections_success(mock_get):
    """
    GIVEN a ConnectionsClient
    WHEN list_connections() is called
    THEN check it calls the API correctly and returns the response
    """
    # Set up mock
    mock_response = (
        {"connections": [{"id": "conn1", "name": "Connection 1"}, {"id": "conn2", "name": "Connection 2"}]},
        200,
    )
    mock_get.return_value = mock_response

    # Call method
    client = ConnectionsClient()
    connections = client.list_connections()

    # Verify
    mock_get.assert_called_once()
    assert len(connections) == 2
    assert connections[0]["id"] == "conn1"
    assert connections[1]["name"] == "Connection 2"


@patch("app.clients.base.BaseClient.get")
def test_list_connections_with_filter(mock_get):
    """
    GIVEN a ConnectionsClient
    WHEN list_connections() is called with a filter
    THEN check it calls the API correctly with the filter
    """
    # Set up mock
    mock_response = ({"connections": [{"id": "conn1", "name": "Connection 1"}]}, 200)
    mock_get.return_value = mock_response

    # Call method
    client = ConnectionsClient()
    connections = client.list_connections(created_by="user123")

    # Verify
    mock_get.assert_called_once()
    assert len(connections) == 1


@patch("app.clients.base.BaseClient.get")
def test_list_connections_error(mock_get):
    """
    GIVEN a ConnectionsClient
    WHEN list_connections() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_get.side_effect = APIError("Failed to fetch connections", 500)

    # Call method and verify exception
    client = ConnectionsClient()
    with pytest.raises(APIError):
        client.list_connections()


@patch("app.clients.base.BaseClient.post")
def test_add_connection_minimal(mock_post):
    """
    GIVEN a ConnectionsClient
    WHEN add_connection() is called with minimal parameters
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = ({"connection_id": "new-conn"}, 201)
    mock_post.return_value = mock_response

    # Call method
    client = ConnectionsClient()
    result = client.add_connection(name="New Connection")

    # Verify
    mock_post.assert_called_once()
    assert result["connection_id"] == "new-conn"


@patch("app.clients.base.BaseClient.post")
def test_add_connection_with_options(mock_post):
    """
    GIVEN a ConnectionsClient
    WHEN add_connection() is called with all parameters
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = ({"connection_id": "new-conn"}, 201)
    mock_post.return_value = mock_response

    # Call method
    client = ConnectionsClient()
    result = client.add_connection(
        name="New Connection", persistent_home=False, desktop_configuration_id=123, external_pvc="my-pvc"
    )

    # Verify
    mock_post.assert_called_once()
    assert result["connection_id"] == "new-conn"


@patch("app.clients.base.BaseClient.post")
def test_add_connection_error(mock_post):
    """
    GIVEN a ConnectionsClient
    WHEN add_connection() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_post.side_effect = APIError("Failed to add connection", 400)

    # Call method and verify exception
    client = ConnectionsClient()
    with pytest.raises(APIError):
        client.add_connection(name="New Connection")


@patch("app.clients.base.BaseClient.post")
def test_stop_connection_success(mock_post):
    """
    GIVEN a ConnectionsClient
    WHEN stop_connection() is called
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = ({"status": "stopped"}, 200)
    mock_post.return_value = mock_response

    # Call method
    client = ConnectionsClient()
    result = client.stop_connection(name="test-connection")

    # Verify
    mock_post.assert_called_once()
    assert result["status"] == "stopped"


@patch("app.clients.base.BaseClient.post")
def test_stop_connection_error(mock_post):
    """
    GIVEN a ConnectionsClient
    WHEN stop_connection() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_post.side_effect = APIError("Failed to stop connection", 404)

    # Call method and verify exception
    client = ConnectionsClient()
    with pytest.raises(APIError):
        client.stop_connection(name="nonexistent-connection")


@patch("app.clients.base.BaseClient.get")
def test_get_connection_success(mock_get):
    """
    GIVEN a ConnectionsClient
    WHEN get_connection() is called
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = ({"connection": {"id": "conn1", "name": "Test Connection", "status": "running"}}, 200)
    mock_get.return_value = mock_response

    # Call method
    client = ConnectionsClient()
    connection = client.get_connection(name="test-connection")

    # Verify
    mock_get.assert_called_once()
    assert connection["id"] == "conn1"
    assert connection["status"] == "running"


@patch("app.clients.base.BaseClient.get")
def test_get_connection_error(mock_get):
    """
    GIVEN a ConnectionsClient
    WHEN get_connection() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_get.side_effect = APIError("Connection not found", 404)

    # Call method and verify exception
    client = ConnectionsClient()
    with pytest.raises(APIError):
        client.get_connection(name="nonexistent-connection")


@patch("app.clients.base.BaseClient.post")
def test_resume_connection_success(mock_post):
    """
    GIVEN a ConnectionsClient
    WHEN resume_connection() is called
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = ({"status": "running"}, 200)
    mock_post.return_value = mock_response

    # Call method
    client = ConnectionsClient()
    result = client.resume_connection(name="test-connection")

    # Verify
    mock_post.assert_called_once()
    assert result["status"] == "running"


@patch("app.clients.base.BaseClient.post")
def test_resume_connection_error(mock_post):
    """
    GIVEN a ConnectionsClient
    WHEN resume_connection() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_post.side_effect = APIError("Failed to resume connection", 404)

    # Call method and verify exception
    client = ConnectionsClient()
    with pytest.raises(APIError):
        client.resume_connection(name="nonexistent-connection")


@patch("app.clients.base.BaseClient.post")
def test_delete_connection_success(mock_post):
    """
    GIVEN a ConnectionsClient
    WHEN delete_connection() is called
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = ({"status": "deleted"}, 200)
    mock_post.return_value = mock_response

    # Call method
    client = ConnectionsClient()
    result = client.delete_connection(name="test-connection")

    # Verify
    mock_post.assert_called_once()
    assert result["status"] == "deleted"


@patch("app.clients.base.BaseClient.post")
def test_delete_connection_error(mock_post):
    """
    GIVEN a ConnectionsClient
    WHEN delete_connection() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_post.side_effect = APIError("Failed to delete connection", 404)

    # Call method and verify exception
    client = ConnectionsClient()
    with pytest.raises(APIError):
        client.delete_connection(name="nonexistent-connection")


@patch("app.clients.base.BaseClient.get")
def test_direct_connect_success(mock_get):
    """
    GIVEN a ConnectionsClient
    WHEN direct_connect() is called
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = ({"auth_token": "abcd1234", "url": "https://example.com/guacamole"}, 200)
    mock_get.return_value = mock_response

    # Call method
    client = ConnectionsClient()
    result = client.direct_connect(connection_id="conn-123")

    # Verify
    mock_get.assert_called_once()
    assert result["auth_token"] == "abcd1234"
    assert result["url"] == "https://example.com/guacamole"


@patch("app.clients.base.BaseClient.get")
def test_direct_connect_error(mock_get):
    """
    GIVEN a ConnectionsClient
    WHEN direct_connect() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_get.side_effect = APIError("Failed to direct connect", 404)

    # Call method and verify exception
    client = ConnectionsClient()
    with pytest.raises(APIError):
        client.direct_connect(connection_id="nonexistent-id")


@patch("app.clients.base.BaseClient.get")
def test_guacamole_dashboard_success(mock_get):
    """
    GIVEN a ConnectionsClient
    WHEN guacamole_dashboard() is called
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = ({"auth_token": "xyz789", "url": "https://example.com/guacamole/admin"}, 200)
    mock_get.return_value = mock_response

    # Call method
    client = ConnectionsClient()
    result = client.guacamole_dashboard()

    # Verify
    mock_get.assert_called_once()
    assert result["auth_token"] == "xyz789"
    assert result["url"] == "https://example.com/guacamole/admin"


@patch("app.clients.base.BaseClient.get")
def test_guacamole_dashboard_error(mock_get):
    """
    GIVEN a ConnectionsClient
    WHEN guacamole_dashboard() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_get.side_effect = APIError("Failed to get dashboard", 500)

    # Call method and verify exception
    client = ConnectionsClient()
    with pytest.raises(APIError):
        client.guacamole_dashboard()
