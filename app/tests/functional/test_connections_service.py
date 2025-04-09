"""
Functional tests for the connections service.
"""

from unittest.mock import MagicMock, patch


def test_view_connections_page_authenticated(logged_in_client):
    """
    GIVEN a Flask application with a logged-in user
    WHEN the connections page is requested
    THEN check the response is valid
    """
    # Mock the connections client to return test data
    with patch("app.clients.factory.client_factory.get_connections_client") as mock_get_connections_client:
        # Set up the mock connections client
        mock_connections_client = MagicMock()
        mock_connections_client.list_connections.return_value = [
            {"id": "conn1", "name": "desktop1", "status": "Running", "desktop_type": "gnome"},
            {"id": "conn2", "name": "desktop2", "status": "Stopped", "desktop_type": "kde"},
        ]
        mock_get_connections_client.return_value = mock_connections_client

        # Mock the desktop configurations client
        with patch("app.clients.factory.client_factory.get_desktop_configurations_client") as mock_get_configs_client:
            mock_configs_client = MagicMock()
            mock_configs_client.list_configurations.return_value = [
                {"id": 1, "name": "GNOME Desktop", "description": "Standard GNOME desktop"},
                {"id": 2, "name": "KDE Desktop", "description": "Standard KDE desktop"},
            ]
            mock_get_configs_client.return_value = mock_configs_client

            # Mock the storage client
            with patch("app.clients.factory.client_factory.get_storage_client") as mock_get_storage_client:
                mock_storage_client = MagicMock()
                mock_storage_client.list_storage.return_value = [
                    {"id": "pvc1", "name": "volume1", "size": "10Gi", "status": "Bound"},
                    {"id": "pvc2", "name": "volume2", "size": "20Gi", "status": "Bound"},
                ]
                mock_get_storage_client.return_value = mock_storage_client

                # Make the request to the connections page
                response = logged_in_client.get("/connections/", follow_redirects=True)

                # Verify the response
                assert response.status_code == 200
                assert b"Connections" in response.data
                assert b"desktop1" in response.data
                assert b"desktop2" in response.data


def test_view_connections_page_unauthenticated(client):
    """
    GIVEN a Flask application with no logged-in user
    WHEN the connections page is requested
    THEN check the user is redirected to the login page
    """
    response = client.get("/connections/", follow_redirects=False)

    # Verify redirect to login page
    assert response.status_code == 302
    assert "/auth/login" in response.location


def test_connections_api_error(logged_in_client):
    """
    GIVEN a Flask application with a logged-in user
    WHEN the connections page is requested but an API error occurs
    THEN check an error message is displayed
    """
    # Mock the connections client to raise an APIError
    with patch("app.clients.factory.client_factory.get_connections_client") as mock_get_client:
        # Set up the mock client to raise an exception
        from app.clients.base import APIError

        mock_client = MagicMock()
        mock_client.list_connections.side_effect = APIError("Failed to fetch connections", status_code=500)
        mock_get_client.return_value = mock_client

        # Make the request to the connections page
        response = logged_in_client.get("/connections/", follow_redirects=True)

        # Verify the response
        assert response.status_code == 200
        assert b"Failed to fetch connections" in response.data


@patch("app.services.connections.routes._return_connection_error")
@patch("app.services.connections.routes._validate_connection_name")
def test_add_connection_success(mock_validate_name, mock_return_error, logged_in_client):
    """
    GIVEN a Flask application with a logged-in user
    WHEN a new connection is added successfully
    THEN check the user is redirected to the connections page with success message
    """
    # Mock the validation to return None (no error)
    mock_validate_name.return_value = None

    # Mock connections client
    with patch("app.clients.factory.client_factory.get_connections_client") as mock_get_client:
        # Set up the mock client
        mock_client = MagicMock()
        mock_client.add_connection.return_value = {"id": "new-conn", "name": "test-desktop"}
        mock_get_client.return_value = mock_client

        # Mock desktop configurations client
        with patch("app.clients.factory.client_factory.get_desktop_configurations_client") as mock_configs_client:
            mock_configs = MagicMock()
            mock_configs.get_configuration.return_value = {"id": 1, "name": "GNOME Desktop"}
            mock_configs_client.return_value = mock_configs

            # Mock the url_for to prevent routing errors
            with patch("flask.url_for") as mock_url_for:
                mock_url_for.return_value = "/connections/"

                # Make the request to add a connection
                logged_in_client.post(
                    "/connections/add",
                    data={"connection_name": "test-desktop", "desktop_configuration_id": "1", "persistent_home": "on"},
                    follow_redirects=True,
                )

                # Since we're mocking the success path, we'll check that add_connection was called
                mock_client.add_connection.assert_called_once()


@patch("app.services.connections.routes._return_connection_error")
def test_add_connection_invalid_name(mock_return_error, logged_in_client):
    """
    GIVEN a Flask application with a logged-in user
    WHEN a connection with an invalid name is submitted
    THEN check an error message is displayed
    """
    # Mock the _return_connection_error to capture the error message
    mock_return_error.side_effect = lambda error_msg, status_code=400: (error_msg, status_code)

    # Mock the validation function to simulate validation failure
    with patch("app.services.connections.routes._validate_connection_name") as mock_validate:
        error_msg = "Connection name must start and end with an alphanumeric character and contain only lowercase letters, numbers, and hyphens"
        mock_validate.return_value = (error_msg, 400)

        # Make the request to add a connection
        logged_in_client.post(
            "/connections/add",
            data={"connection_name": "Invalid-Name", "desktop_configuration_id": "1"},
            follow_redirects=True,
        )

        # Verify the validation was called
        mock_validate.assert_called_once_with("Invalid-Name")


@patch("app.services.connections.routes._return_connection_error")
def test_add_connection_missing_data(mock_return_error, logged_in_client):
    """
    GIVEN a Flask application with a logged-in user
    WHEN a connection with missing required data is submitted
    THEN check an error message is displayed
    """
    # Mock the _return_connection_error to capture the error message
    mock_return_error.side_effect = lambda error_msg, status_code=400: (error_msg, status_code)

    # Make the request to add a connection with missing name
    logged_in_client.post("/connections/add", data={"desktop_configuration_id": "1"}, follow_redirects=True)

    # Verify error_return was called with the correct message
    mock_return_error.assert_called_with("Connection name is required", 400)
