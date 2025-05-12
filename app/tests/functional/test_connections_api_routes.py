"""
This module contains functional tests for the connections API routes.
"""
import pytest
from unittest.mock import patch, MagicMock, ANY


@patch("clients.factory.client_factory.get_connections_client")
def test_list_connections_unauthorized(mock_connections_client, client):
    """
    GIVEN an unauthenticated user
    WHEN the connections API endpoint is requested
    THEN check that access is denied
    """
    response = client.get("/api/connections/")
    assert response.status_code == 403
    assert "You need to log in to access this page" in response.data.decode("utf-8")


@patch("clients.factory.client_factory.get_connections_client")
def test_list_connections_authenticated(mock_connections_client, logged_in_client):
    """
    GIVEN a logged-in user
    WHEN the connections API endpoint is requested
    THEN check that connections are returned
    """
    # Create mock client
    mock_client = MagicMock()
    mock_connections_client.return_value = mock_client

    # Configure mock response
    mock_client.list_connections.return_value = [
        {
            "id": "conn1",
            "name": "test-conn-1",
            "status": "Ready",
            "created_at": "2023-01-01T12:00:00Z",
            "desktop_configuration": {"name": "Standard"},
        },
        {
            "id": "conn2",
            "name": "test-conn-2",
            "status": "Running",
            "created_at": "2023-01-02T12:00:00Z",
            "desktop_configuration": {"name": "Performance"},
        },
    ]

    # Access connections API endpoint
    response = logged_in_client.get("/api/connections/")

    # Check response
    assert response.status_code == 200
    data = response.get_json()
    assert "connections" in data
    assert len(data["connections"]) == 2
    assert data["connections"][0]["name"] == "test-conn-1"
    assert data["connections"][1]["status"] == "Running"

    # Verify the mock was called correctly
    mock_client.list_connections.assert_called_once_with(None, token=ANY)


@patch("clients.factory.client_factory.get_connections_client")
def test_list_connections_admin_filter_by_username(mock_connections_client, admin_client):
    """
    GIVEN a logged-in admin user
    WHEN the connections API endpoint is requested with a username filter
    THEN check that connections for that user are returned
    """
    # Create mock client
    mock_client = MagicMock()
    mock_connections_client.return_value = mock_client

    # Configure mock response
    mock_client.list_connections.return_value = [
        {
            "id": "conn1",
            "name": "test-conn-1",
            "status": "Ready",
            "created_at": "2023-01-01T12:00:00Z",
            "desktop_configuration": {"name": "Standard"},
            "username": "testuser",
        }
    ]

    # Access connections API endpoint with username filter
    response = admin_client.get("/api/connections/?username=testuser")

    # Check response
    assert response.status_code == 200
    data = response.get_json()
    assert "connections" in data
    assert len(data["connections"]) == 1
    assert data["connections"][0]["username"] == "testuser"

    # Verify the mock was called correctly with the username parameter
    mock_client.list_connections.assert_called_once_with("testuser", token=ANY)


@patch("clients.factory.client_factory.get_connections_client")
def test_create_connection_success(mock_connections_client, logged_in_client):
    """
    GIVEN a logged-in user
    WHEN a connection creation request is made with valid data
    THEN check that the connection is created successfully
    """
    # Create mock client
    mock_client = MagicMock()
    mock_connections_client.return_value = mock_client

    # Mock successful connection creation
    mock_client.add_connection.return_value = {"id": "new-conn"}

    # Connection data
    connection_data = {"connection_name": "test-conn", "persistent_home": True, "desktop_configuration_id": "config1"}

    # Make the request
    response = logged_in_client.post("/api/connections/", json=connection_data)

    # Check response
    assert response.status_code == 201
    data = response.get_json()
    assert "status" in data
    assert data["status"] == "success"
    assert "message" in data
    assert "created successfully" in data["message"]

    # Verify the mock was called correctly with the right parameters
    mock_client.add_connection.assert_called_once()
    call_kwargs = mock_client.add_connection.call_args[1]
    assert call_kwargs["name"] == "test-conn"
    assert call_kwargs["persistent_home"] is True
    assert call_kwargs["desktop_configuration_id"] == "config1"
    assert "token" in call_kwargs


@patch("clients.factory.client_factory.get_connections_client")
def test_create_connection_missing_name(mock_connections_client, logged_in_client):
    """
    GIVEN a logged-in user
    WHEN a connection creation request is made without a name
    THEN check that an error is returned
    """
    # Connection data missing name
    connection_data = {"persistent_home": True, "desktop_configuration_id": "config1"}

    # Make the request
    response = logged_in_client.post("/api/connections/", json=connection_data)

    # Check response
    assert response.status_code == 400
    data = response.get_json()
    assert "error" in data
    assert "Connection name is required" in data["error"]


@patch("clients.factory.client_factory.get_connections_client")
def test_create_connection_invalid_name(mock_connections_client, logged_in_client):
    """
    GIVEN a logged-in user
    WHEN a connection creation request is made with an invalid name
    THEN check that an error is returned
    """
    # Connection data with invalid name (uppercase not allowed)
    connection_data = {"connection_name": "Test-Conn", "persistent_home": True, "desktop_configuration_id": "config1"}

    # Make the request
    response = logged_in_client.post("/api/connections/", json=connection_data)

    # Check response
    assert response.status_code == 400
    data = response.get_json()
    assert "error" in data
    assert "must start and end with an alphanumeric character" in data["error"]


@patch("clients.factory.client_factory.get_connections_client")
def test_create_connection_name_too_long(mock_connections_client, logged_in_client):
    """
    GIVEN a logged-in user
    WHEN a connection creation request is made with a name that's too long
    THEN check that an error is returned
    """
    # Connection data with name that exceeds maximum length
    connection_data = {
        "connection_name": "test-connection-with-very-long-name",
        "persistent_home": True,
        "desktop_configuration_id": "config1",
    }

    # Make the request
    response = logged_in_client.post("/api/connections/", json=connection_data)

    # Check response
    assert response.status_code == 400
    data = response.get_json()
    assert "error" in data
    assert "name is too long" in data["error"]


# @pytest.mark.skip("This test is failing due to issues with the test environment")
@patch("clients.factory.client_factory.get_connections_client")
def test_stop_connection_success(mock_connections_client, logged_in_client):
    """
    GIVEN a logged-in user
    WHEN a stop connection request is made
    THEN check that the API call is attempted
    """
    # Create mock client
    mock_client = MagicMock()
    mock_connections_client.return_value = mock_client

    # Configure the mock to handle the stop operation successfully
    mock_client.stop_connection.return_value = {"status": "success"}

    # Connection name
    connection_name = "test-conn"

    # Make the request
    response = logged_in_client.post(f"/api/connections/{connection_name}/stop", json={})

    # Verify the mock was called
    mock_client.stop_connection.assert_called_once_with(connection_name, token=ANY)


@patch("clients.factory.client_factory.get_connections_client")
def test_resume_connection_success(mock_connections_client, logged_in_client):
    """
    GIVEN a logged-in user
    WHEN a resume connection request is made
    THEN check that the API call is attempted
    """
    # Create mock client
    mock_client = MagicMock()
    mock_connections_client.return_value = mock_client

    # Configure the mock to handle the resume operation successfully
    mock_client.resume_connection.return_value = {"status": "success"}

    # Connection name
    connection_name = "test-conn"

    # Make the request
    response = logged_in_client.post(f"/api/connections/{connection_name}/resume", json={})

    # Check response
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert "message" in data
    assert "resumed successfully" in data["message"]

    # Verify the mock was called
    mock_client.resume_connection.assert_called_once_with(connection_name, token=ANY)


@patch("clients.factory.client_factory.get_connections_client")
def test_delete_connection_success(mock_connections_client, logged_in_client):
    """
    GIVEN a logged-in user
    WHEN a delete connection request is made
    THEN check that the connection is deleted successfully
    """
    # Create mock client
    mock_client = MagicMock()
    mock_connections_client.return_value = mock_client

    # Configure the mock to handle the delete operation successfully
    mock_client.delete_connection.return_value = {"status": "success"}

    # Connection name
    connection_name = "test-conn"

    # Make the request
    response = logged_in_client.delete(f"/api/connections/{connection_name}")

    # Check response
    assert response.status_code == 200
    data = response.get_json()
    assert "status" in data
    assert data["status"] == "success"

    # Verify the mock was called correctly
    mock_client.delete_connection.assert_called_once_with(connection_name, token=ANY)


@patch("clients.factory.client_factory.get_connections_client")
def test_get_dashboard_auth_url(mock_connections_client, logged_in_client):
    """
    GIVEN a logged-in user
    WHEN a request for the Guacamole dashboard auth URL is made
    THEN check that the URL is returned correctly
    """
    # Create mock client
    mock_client = MagicMock()
    mock_connections_client.return_value = mock_client

    # Configure mock response
    mock_client.guacamole_dashboard.return_value = {
        "auth_url": "https://guacamole.example.com/guacamole/#/?token=dashboard-token"
    }

    # Make the request
    response = logged_in_client.get("/api/connections/dashboard-auth-url")

    # Check response
    assert response.status_code == 200
    data = response.get_json()
    assert "auth_url" in data
    assert "guacamole.example.com" in data["auth_url"]
    assert "token=dashboard-token" in data["auth_url"]

    # Verify the mock was called correctly
    mock_client.guacamole_dashboard.assert_called_once_with(token=ANY)


@patch("clients.factory.client_factory.get_connections_client")
def test_attach_pvc_success(mock_connections_client, logged_in_client):
    """
    GIVEN a logged-in user
    WHEN a request to attach a PVC to a connection is made
    THEN check that the PVC is attached successfully
    """
    # Create mock client
    mock_client = MagicMock()
    mock_connections_client.return_value = mock_client

    # Configure mock response
    mock_client.attach_pvc_to_connection.return_value = {"message": "PVC attached successfully"}

    # Request data
    request_data = {"connection_id": "conn1", "pvc_id": "pvc1"}

    # Make the request
    response = logged_in_client.post("/api/connections/attach-pvc", json=request_data)

    # Check response
    assert response.status_code == 200
    data = response.get_json()
    assert "message" in data
    assert "attached successfully" in data["message"]

    # Verify the mock was called correctly
    mock_client.attach_pvc_to_connection.assert_called_once_with("conn1", "pvc1", token=ANY)


@patch("clients.factory.client_factory.get_connections_client")
def test_detach_pvc_success(mock_connections_client, logged_in_client):
    """
    GIVEN a logged-in user
    WHEN a request to detach a PVC from a connection is made
    THEN check that the PVC is detached successfully
    """
    # Create mock client
    mock_client = MagicMock()
    mock_connections_client.return_value = mock_client

    # Configure mock response
    mock_client.detach_pvc_from_connection.return_value = {"message": "PVC detached successfully"}

    # Request data
    request_data = {"connection_id": "conn1"}

    # Make the request
    response = logged_in_client.post("/api/connections/detach-pvc", json=request_data)

    # Check response
    assert response.status_code == 200
    data = response.get_json()
    assert "message" in data
    assert "detached successfully" in data["message"]

    # Verify the mock was called correctly
    mock_client.detach_pvc_from_connection.assert_called_once_with("conn1", token=ANY)


@patch("clients.factory.client_factory.get_connections_client")
def test_api_error_handling_in_connections(mock_connections_client, logged_in_client):
    """
    GIVEN a logged-in user
    WHEN the API returns an error
    THEN check that error is properly handled
    """
    from clients.base import APIError

    # Create mock client
    mock_client = MagicMock()
    mock_connections_client.return_value = mock_client

    # Configure mock to raise an API error
    api_error = APIError("Connection not found", status_code=404)
    mock_client.list_connections.side_effect = api_error

    # Access connections API endpoint
    response = logged_in_client.get("/api/connections/")

    # Check response
    assert response.status_code == 404
    data = response.get_json()
    assert "error" in data
    assert data["error"] == "Connection not found"
