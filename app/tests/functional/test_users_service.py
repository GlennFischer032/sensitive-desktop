"""
Functional tests for the users service.
"""

from unittest.mock import patch, MagicMock


def test_view_users_page_as_admin(admin_client):
    """
    GIVEN a Flask application with a logged-in admin
    WHEN the users page is requested
    THEN check the response is valid
    """
    # Mock the users client to return test data
    with patch("app.clients.factory.client_factory.get_users_client") as mock_get_client:
        # Set up the mock client
        mock_client = MagicMock()
        mock_client.list_users.return_value = [
            {"id": "user1", "username": "user1", "email": "user1@example.com", "is_admin": False},
            {"id": "user2", "username": "user2", "email": "user2@example.com", "is_admin": True},
        ]
        mock_get_client.return_value = mock_client

        # Make the request to the users page
        response = admin_client.get("/users/", follow_redirects=True)

        # Verify the response
        assert response.status_code == 200
        assert b"Users" in response.data
        assert b"user1" in response.data
        assert b"user2" in response.data


def test_view_users_page_as_regular_user(logged_in_client):
    """
    GIVEN a Flask application with a logged-in regular user
    WHEN the users page is requested
    THEN check the user is redirected to the connections page
    """
    response = logged_in_client.get("/users/", follow_redirects=True)

    # Should be redirected with an error message
    assert response.status_code == 200
    assert b"You need administrator privileges" in response.data


def test_view_users_page_unauthenticated(client):
    """
    GIVEN a Flask application with no logged-in user
    WHEN the users page is requested
    THEN check the user is redirected to the login page
    """
    response = client.get("/users/", follow_redirects=False)

    # Verify redirect to login page
    assert response.status_code == 302
    assert "/auth/login" in response.location


def test_view_users_api_error(admin_client):
    """
    GIVEN a Flask application with a logged-in admin
    WHEN the users page is requested but an API error occurs
    THEN check an error message is displayed
    """
    # Mock the users client to raise an APIError
    with patch("app.clients.factory.client_factory.get_users_client") as mock_get_client:
        # Set up the mock client to raise an exception
        from app.clients.base import APIError

        mock_client = MagicMock()
        mock_client.list_users.side_effect = APIError("Failed to fetch users", status_code=500)
        mock_get_client.return_value = mock_client

        # Make the request to the users page
        response = admin_client.get("/users/", follow_redirects=True)

        # Verify the response
        assert response.status_code == 200
        assert b"Failed to fetch users" in response.data


def test_dashboard_page_as_admin(admin_client):
    """
    GIVEN a Flask application with a logged-in admin
    WHEN the dashboard page is requested
    THEN check the response is valid
    """
    # Mock the users client to return test data
    with patch("app.clients.factory.client_factory.get_users_client") as mock_get_client:
        # Set up the mock client
        mock_client = MagicMock()
        mock_client.list_users.return_value = [
            {"id": "user1", "username": "user1", "email": "user1@example.com", "is_admin": False},
            {"id": "user2", "username": "user2", "email": "user2@example.com", "is_admin": True},
        ]
        mock_get_client.return_value = mock_client

        # Make the request to the dashboard page
        response = admin_client.get("/users/dashboard", follow_redirects=True)

        # Verify the response
        assert response.status_code == 200
        assert b"Dashboard" in response.data


def test_dashboard_page_as_regular_user(logged_in_client):
    """
    GIVEN a Flask application with a logged-in regular user
    WHEN the dashboard page is requested
    THEN check the user is blocked from accessing it
    """
    response = logged_in_client.get("/users/dashboard", follow_redirects=True)

    # Should be redirected with an error message
    assert response.status_code == 200
    assert b"You need administrator privileges" in response.data


def test_dashboard_api_error(admin_client):
    """
    GIVEN a Flask application with a logged-in admin
    WHEN the dashboard page is requested but an API error occurs
    THEN check an error message is displayed
    """
    # Mock the users client to raise an APIError
    with patch("app.clients.factory.client_factory.get_users_client") as mock_get_client:
        # Set up the mock client to raise an exception
        from app.clients.base import APIError

        mock_client = MagicMock()
        mock_client.list_users.side_effect = APIError("Failed to fetch users", status_code=500)
        mock_get_client.return_value = mock_client

        # Make the request to the dashboard page
        response = admin_client.get("/users/dashboard", follow_redirects=True)

        # Verify the response
        assert response.status_code == 200
        assert b"Failed to fetch users list" in response.data
