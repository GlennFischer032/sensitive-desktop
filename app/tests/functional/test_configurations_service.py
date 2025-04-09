"""
Functional tests for the configurations service.
"""

from unittest.mock import MagicMock, patch


def test_list_configurations_authenticated(logged_in_client):
    """
    GIVEN a Flask application with a logged-in user
    WHEN the configurations page is requested
    THEN check the response is valid
    """
    # Mock the desktop configurations client to return test data
    with patch("app.clients.factory.client_factory.get_desktop_configurations_client") as mock_get_client:
        # Set up the mock client
        mock_client = MagicMock()
        mock_client.list_configurations.return_value = [
            {"id": 1, "name": "GNOME Desktop", "description": "Standard GNOME desktop"},
            {"id": 2, "name": "KDE Desktop", "description": "Standard KDE desktop"},
        ]
        mock_client.get_users.return_value = {
            "data": [
                {"id": "user1", "username": "user1"},
                {"id": "user2", "username": "user2"},
            ]
        }
        mock_get_client.return_value = mock_client

        # Make the request to the configurations page
        response = logged_in_client.get("/configurations/", follow_redirects=True)

        # Verify the response
        assert response.status_code == 200
        assert b"Desktop Configurations" in response.data or b"Configurations" in response.data
        assert b"GNOME Desktop" in response.data
        assert b"KDE Desktop" in response.data


def test_list_configurations_unauthenticated(client):
    """
    GIVEN a Flask application with no logged-in user
    WHEN the configurations page is requested
    THEN check the user is redirected to the login page
    """
    response = client.get("/configurations/", follow_redirects=False)

    # Verify redirect to login page
    assert response.status_code == 302
    assert "/auth/login" in response.location


def test_list_configurations_api_error(logged_in_client):
    """
    GIVEN a Flask application with a logged-in user
    WHEN the configurations page is requested but an API error occurs
    THEN check an error message is displayed
    """
    # Mock the desktop configurations client to raise an APIError
    with patch("app.clients.factory.client_factory.get_desktop_configurations_client") as mock_get_client:
        # Set up the mock client to raise an exception
        from app.clients.base import APIError

        mock_client = MagicMock()
        mock_client.list_configurations.side_effect = APIError("Failed to fetch configurations", status_code=500)
        mock_get_client.return_value = mock_client

        # Make the request to the configurations page
        response = logged_in_client.get("/configurations/", follow_redirects=True)

        # Verify the response
        assert response.status_code == 200
        assert b"Error listing configurations" in response.data


def test_list_configurations_users_api_error(logged_in_client):
    """
    GIVEN a Flask application with a logged-in user
    WHEN the configurations page is requested but an API error occurs fetching users
    THEN check the page still loads with configurations but without users
    """
    # Mock the desktop configurations client to return configurations but raise error for users
    with patch("app.clients.factory.client_factory.get_desktop_configurations_client") as mock_get_client:
        # Set up the mock client
        mock_client = MagicMock()
        mock_client.list_configurations.return_value = [
            {"id": 1, "name": "GNOME Desktop", "description": "Standard GNOME desktop"},
        ]
        from app.clients.base import APIError

        mock_client.get_users.side_effect = APIError("Failed to fetch users", status_code=500)
        mock_get_client.return_value = mock_client

        # Make the request to the configurations page
        response = logged_in_client.get("/configurations/", follow_redirects=True)

        # Verify the response
        assert response.status_code == 200
        assert b"GNOME Desktop" in response.data  # Should still show configurations
