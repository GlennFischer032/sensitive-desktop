"""
This module contains functional tests for API error handling.
"""
import pytest
from unittest.mock import patch, MagicMock
from clients.base import APIError
from flask import jsonify


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
    api_error = APIError(message="Connection with this name already exists", status_code=409)
    mock_conn_client.add_connection.side_effect = api_error

    # Mock error handling function to return a string (prevents redirect)
    mock_return_error.return_value = "Error handled"

    # Submit a new connection request
    with patch.object(logged_in_client.application, "handle_exception", return_value="Error handled"):
        response = logged_in_client.post(
            "/connections/add",
            data={
                "connection_name": "test-conn",
                "desktop_configuration_id": "config1",
            },
        )

    # Verify the add_connection function was called
    mock_conn_client.add_connection.assert_called_once()

    # Verify error handler was called with the correct parameters
    mock_return_error.assert_called()
    error_args = mock_return_error.call_args
    assert "Connection with this name already exists" in str(error_args)
    assert "409" in str(error_args) or 409 in str(error_args)


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
    api_error = APIError(message="Invalid configuration", status_code=400)
    mock_conn_client.add_connection.side_effect = api_error

    # Patch the _return_connection_error to directly return the error
    with patch(
        "services.connections.routes._return_connection_error",
        return_value=(jsonify({"status": "error", "error": "Invalid configuration"}), 400),
    ):
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
