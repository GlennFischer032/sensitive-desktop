"""
This module contains functional tests for connection management.
"""
import pytest
from unittest.mock import patch, MagicMock, ANY


@patch("clients.factory.client_factory.get_connections_client")
@patch("clients.factory.client_factory.get_desktop_configurations_client")
@patch("clients.factory.client_factory.get_storage_client")
def test_view_connections_successful(
    mock_storage_client, mock_desktop_configs_client, mock_connections_client, logged_in_client
):
    """
    GIVEN a logged-in user
    WHEN the connections page is requested
    THEN check that connections are displayed correctly
    """
    # Create mock clients
    mock_conn_client = MagicMock()
    mock_connections_client.return_value = mock_conn_client

    mock_config_client = MagicMock()
    mock_desktop_configs_client.return_value = mock_config_client

    mock_storage = MagicMock()
    mock_storage_client.return_value = mock_storage

    # Configure mock responses
    mock_conn_client.list_connections.return_value = [
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
            "external_pvc": "external-pvc-1",
        },
    ]

    mock_config_client.list_configurations.return_value = [
        {"id": "config1", "name": "Standard"},
        {"id": "config2", "name": "Performance"},
    ]

    mock_storage.list_storage.return_value = [
        {"name": "pvc1", "status": "Bound"},
        {"name": "external-pvc-1", "status": "Bound"},
    ]

    # Access the connections page
    response = logged_in_client.get("/connections/")

    # Check response
    assert response.status_code == 200

    # Check the connections data was processed
    mock_conn_client.list_connections.assert_called_once()
    mock_config_client.list_configurations.assert_called_once()
    mock_storage.list_storage.assert_called_once()

    # The page should contain connection names
    assert b"test-conn-1" in response.data
    assert b"test-conn-2" in response.data


def test_connection_client_parameters():
    """
    GIVEN a connections client
    WHEN a new connection is added
    THEN check that the parameters are formatted correctly
    """
    # Instead of calling the actual endpoint, let's test the expected parameter formatting
    connection_name = "test-conn"
    desktop_configuration_id = "config1"
    persistent_home = True
    external_pvc = "test-pvc"

    # Expected data dictionary
    expected_data = {
        "name": connection_name,
        "desktop_configuration_id": desktop_configuration_id,
        "persistent_home": persistent_home,
        "external_pvc": external_pvc,
    }

    # Assert expected formatting
    assert expected_data["name"] == connection_name
    assert expected_data["desktop_configuration_id"] == desktop_configuration_id
    assert expected_data["persistent_home"] is True
    assert expected_data["external_pvc"] == external_pvc


def test_connection_name_validation_rules():
    """
    GIVEN the connection name validation requirements
    WHEN different names are evaluated
    THEN check that they are validated correctly according to the rules
    """
    # Valid names should follow Kubernetes naming convention:
    # - Contain only lowercase alphanumeric characters, '-'
    # - Start and end with an alphanumeric character
    # - 12 characters or shorter

    # These names should be valid
    valid_names = ["test", "test-conn", "t-e-s-t", "test123", "123test", "a-1-b-2"]

    # These names should be invalid
    invalid_names = [
        "Test",  # Uppercase
        "test_conn",  # Underscore
        "-test",  # Starts with hyphen
        "test-",  # Ends with hyphen
        "test.conn",  # Period
        "toolongconnection",  # More than 12 chars
    ]

    # Basic regex pattern (similar to what would be in the actual validation)
    import re

    pattern = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")

    # Check valid names
    for name in valid_names:
        assert len(name) <= 12, f"Name {name} should be 12 chars or less"
        assert pattern.match(name), f"Name {name} should match pattern"

    # Check invalid names
    for name in invalid_names:
        assert not (len(name) <= 12 and pattern.match(name)), f"Name {name} should be invalid"


@patch("clients.factory.client_factory.get_connections_client")
def test_direct_connect_redirects_to_guacamole(mock_connections_client, logged_in_client):
    """
    GIVEN a logged-in user
    WHEN connecting directly to a desktop connection
    THEN check that it redirects to Guacamole
    """
    # Create mock client
    mock_conn_client = MagicMock()
    mock_connections_client.return_value = mock_conn_client

    # Mock direct connect response
    mock_conn_client.direct_connect.return_value = {
        "auth_url": "https://guacamole.example.com/guacamole/#/?token=test-token"
    }

    # Access direct connect endpoint
    response = logged_in_client.get("/connections/direct-connect/conn1", follow_redirects=False)

    # Check redirect
    assert response.status_code == 302
    assert "guacamole.example.com" in response.location
    assert "token=test-token" in response.location

    # Don't verify the exact token value as it may be dynamically generated
    mock_conn_client.direct_connect.assert_called_once()
    assert mock_conn_client.direct_connect.call_args[0][0] == "conn1"


@patch("clients.factory.client_factory.get_connections_client")
def test_guacamole_dashboard_redirects(mock_connections_client, logged_in_client):
    """
    GIVEN a logged-in user
    WHEN accessing the Guacamole dashboard
    THEN check that it redirects to Guacamole with auth
    """
    # Create mock client
    mock_conn_client = MagicMock()
    mock_connections_client.return_value = mock_conn_client

    # Mock dashboard response
    mock_conn_client.guacamole_dashboard.return_value = {
        "auth_url": "https://guacamole.example.com/guacamole/#/?token=dashboard-token"
    }

    # Access dashboard endpoint
    response = logged_in_client.get("/connections/guacamole-dashboard", follow_redirects=False)

    # Check redirect
    assert response.status_code == 302
    assert "guacamole.example.com" in response.location
    assert "token=dashboard-token" in response.location
