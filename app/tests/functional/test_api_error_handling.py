"""
This module contains functional tests for API error handling.
"""
import pytest
from unittest.mock import patch, MagicMock
from clients.base import APIError


@patch("clients.factory.client_factory.get_connections_client")
def test_api_error_handling_in_connections(mock_connections_client, logged_in_client):
    """
    GIVEN a logged-in user
    WHEN an API error occurs while fetching connections
    THEN check that the error is handled appropriately
    """
    # Create mock client
    mock_conn_client = MagicMock()
    mock_connections_client.return_value = mock_conn_client

    # Mock API error
    mock_conn_client.list_connections.side_effect = APIError(message="API connection timeout", status_code=500)

    # Access the connections page
    response = logged_in_client.get("/connections/")

    # Should still render the page
    assert response.status_code == 200

    # Should display the error message
    assert b"Failed to fetch connections" in response.data
    assert b"API connection timeout" in response.data


@patch("services.connections.routes._return_connection_error")
@patch("clients.factory.client_factory.get_connections_client")
def test_connection_add_api_error_handled(mock_connections_client, mock_return_error, logged_in_client):
    """
    GIVEN a logged-in user
    WHEN an API error occurs while adding a connection
    THEN check that the error is handled by the error handling function
    """
    # Create mock client
    mock_conn_client = MagicMock()
    mock_connections_client.return_value = mock_conn_client

    # Mock API error
    mock_conn_client.add_connection.side_effect = APIError(
        message="Connection with this name already exists", status_code=409
    )

    # Mock error handling function
    mock_return_error.return_value = "Error handled response"

    # Submit a new connection request (ignore actual response as we're checking the error handler)
    try:
        logged_in_client.post(
            "/connections/add",
            data={
                "connection_name": "test-conn",
                "desktop_configuration_id": "config1",
            },
        )
    except Exception:
        # Ignore any view function errors
        pass

    # Verify the error handling function was called with the correct error message
    mock_conn_client.add_connection.assert_called_once()
    assert mock_return_error.called
    error_args = mock_return_error.call_args
    assert "Connection with this name already exists" in str(error_args)
    assert "409" in str(error_args) or 409 in error_args


@patch("clients.factory.client_factory.get_connections_client")
def test_ajax_error_handling(mock_connections_client, logged_in_client):
    """
    GIVEN a logged-in user making an AJAX request
    WHEN an API error occurs
    THEN check that a JSON error response is returned
    """
    # Create mock client
    mock_conn_client = MagicMock()
    mock_connections_client.return_value = mock_conn_client

    # Mock API error
    mock_conn_client.add_connection.side_effect = APIError(message="Invalid configuration", status_code=400)

    # Submit AJAX request
    response = logged_in_client.post(
        "/connections/add",
        data={
            "connection_name": "test-conn",
            "desktop_configuration_id": "config1",
        },
        headers={"X-Requested-With": "XMLHttpRequest"},
    )

    # Check response is JSON with error info
    assert response.status_code == 400
    assert response.is_json
    json_data = response.get_json()
    assert json_data["status"] == "error"
    assert json_data["error"] == "Invalid configuration"


@patch("clients.factory.client_factory.get_connections_client")
def test_direct_connect_error_handling(mock_connections_client, logged_in_client):
    """
    GIVEN a logged-in user
    WHEN an error occurs while connecting to a desktop
    THEN check that the user is redirected with an error message
    """
    # Create mock client
    mock_conn_client = MagicMock()
    mock_connections_client.return_value = mock_conn_client

    # Mock exception
    mock_conn_client.direct_connect.side_effect = Exception("Connection failed")

    # Access direct connect endpoint
    response = logged_in_client.get("/connections/direct-connect/conn1", follow_redirects=True)

    # Should redirect to connections page with error
    assert response.status_code == 200
    assert b"Error connecting to desktop: Connection failed" in response.data
