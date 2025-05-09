"""
This module contains functional tests for user management API routes.
"""
import pytest
from unittest.mock import patch, MagicMock, ANY


@patch("clients.factory.client_factory.get_users_client")
def test_list_users_unauthorized(mock_users_client, client):
    """
    GIVEN an unauthenticated user
    WHEN the users API endpoint is requested
    THEN check that access is denied
    """
    response = client.get("/api/users/")
    assert response.status_code == 302  # Redirect to login page


@patch("clients.factory.client_factory.get_users_client")
def test_list_users_non_admin(mock_users_client, logged_in_client):
    """
    GIVEN a logged-in non-admin user
    WHEN the users API endpoint is requested
    THEN check that access is denied via redirect
    """
    # Flask test environment redirects instead of showing 403 directly
    # in many cases due to how middleware and decorators work in test mode
    response = logged_in_client.get("/api/users/")

    # Verify redirect happens (indicating access control enforcement)
    assert response.status_code == 302


@patch("clients.factory.client_factory.get_users_client")
def test_list_users_admin(mock_users_client, admin_client):
    """
    GIVEN a logged-in admin user
    WHEN the users API endpoint is requested
    THEN check that users are returned
    """
    # Create mock client
    mock_client = MagicMock()
    mock_users_client.return_value = mock_client

    # Configure mock response
    mock_client.list_users.return_value = [
        {"username": "user1", "is_admin": False, "email": "user1@example.com"},
        {"username": "user2", "is_admin": True, "email": "user2@example.com"},
    ]

    # Access users API endpoint
    response = admin_client.get("/api/users/")

    # Check response
    assert response.status_code == 200
    data = response.get_json()
    assert "users" in data
    assert len(data["users"]) == 2
    assert data["users"][0]["username"] == "user1"
    assert data["users"][1]["username"] == "user2"
    assert data["users"][1]["is_admin"] is True

    # Verify the mock was called correctly
    mock_client.list_users.assert_called_once_with(token=ANY)


@patch("clients.factory.client_factory.get_users_client")
def test_get_user_admin(mock_users_client, admin_client):
    """
    GIVEN a logged-in admin user
    WHEN a specific user's details are requested
    THEN check that user details are returned
    """
    username = "testuser"

    # Create mock clients
    mock_client = MagicMock()
    mock_users_client.return_value = mock_client

    # Configure mock response
    mock_client.get_user.return_value = {"username": username, "is_admin": False, "email": "testuser@example.com"}

    # Access user details API endpoint
    with patch("clients.factory.client_factory.get_connections_client") as mock_connections_client:
        # Mock connections client to return empty list
        mock_conn_client = MagicMock()
        mock_connections_client.return_value = mock_conn_client
        mock_conn_client.list_connections.return_value = []

        response = admin_client.get(f"/api/users/{username}")

    # Check response
    assert response.status_code == 200
    data = response.get_json()
    assert "user" in data
    assert data["user"]["username"] == username
    assert "user_connections" in data

    # Verify the mock was called correctly
    mock_client.get_user.assert_called_once_with(username, token=ANY)


@patch("clients.factory.client_factory.get_users_client")
def test_create_user_admin(mock_users_client, admin_client):
    """
    GIVEN a logged-in admin user
    WHEN a new user creation request is made
    THEN check that user is created successfully
    """
    # Create mock client
    mock_client = MagicMock()
    mock_users_client.return_value = mock_client

    # Mock successful user creation
    mock_client.add_user.return_value = {"success": True}

    # User data
    user_data = {"username": "newuser", "sub": "sub123456", "is_admin": False}

    # Make the request
    response = admin_client.post("/api/users/", json=user_data)

    # Check response
    assert response.status_code == 201
    data = response.get_json()
    assert "message" in data
    assert "user" in data
    assert data["user"]["username"] == "newuser"
    assert data["user"]["is_admin"] is False
    assert data["user"]["sub"] == "sub123456"

    # Verify the mock was called correctly with the right parameters
    mock_client.add_user.assert_called_once_with(username="newuser", sub="sub123456", is_admin=False, token=ANY)


@patch("clients.factory.client_factory.get_users_client")
def test_create_user_missing_data(mock_users_client, admin_client):
    """
    GIVEN a logged-in admin user
    WHEN a user creation request is made with missing data
    THEN check that an error is returned
    """
    # Incomplete user data
    user_data = {
        "username": "newuser"
        # Missing sub field
    }

    # Make the request
    response = admin_client.post("/api/users/", json=user_data)

    # Check response
    assert response.status_code == 400
    data = response.get_json()
    assert "error" in data
    assert "Username and OIDC Subject Identifier are required" in data["error"]


@patch("clients.factory.client_factory.get_users_client")
def test_delete_user_admin(mock_users_client, admin_client):
    """
    GIVEN a logged-in admin user
    WHEN a user deletion request is made
    THEN check that user is deleted successfully
    """
    username = "userToDelete"

    # Create mock client
    mock_client = MagicMock()
    mock_users_client.return_value = mock_client

    # Mock successful user deletion
    mock_client.delete_user.return_value = {"success": True}

    # Make the request
    response = admin_client.delete(f"/api/users/{username}")

    # Check response
    assert response.status_code == 200
    data = response.get_json()
    assert "message" in data
    assert "deleted successfully" in data["message"]

    # Verify the mock was called correctly
    mock_client.delete_user.assert_called_once_with(username, token=ANY)


@patch("clients.factory.client_factory.get_users_client")
def test_delete_self_not_allowed(mock_users_client, admin_client):
    """
    GIVEN a logged-in admin user
    WHEN trying to delete their own account
    THEN check that an error is returned
    """
    # Set up the test conditions
    with admin_client.application.test_request_context():
        # Access admin_client via the application context
        from flask import session

        # Modify the session in the test context
        session["username"] = "admin_user"
        session.modified = True

        # Create a deletion request in the same application context
        client = admin_client.application.test_client()
        with client.session_transaction() as sess:
            sess["username"] = "admin_user"
            sess["logged_in"] = True
            sess["is_admin"] = True
            sess["token"] = "test-token"

        # Make the request to delete own account
        response = client.delete("/api/users/admin_user")

        # Check response
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data
        assert "Cannot delete your own account" in data["error"]


@patch("clients.factory.client_factory.get_users_client")
def test_api_error_handling(mock_users_client, admin_client):
    """
    GIVEN a logged-in admin user
    WHEN the API returns an error
    THEN check that error is properly handled
    """
    from clients.base import APIError

    # Create mock client
    mock_client = MagicMock()
    mock_users_client.return_value = mock_client

    # Configure mock to raise an API error
    api_error = APIError("API server error", status_code=500)
    mock_client.list_users.side_effect = api_error

    # Access users API endpoint
    response = admin_client.get("/api/users/")

    # Check response
    assert response.status_code == 500
    data = response.get_json()
    assert "error" in data
    assert data["error"] == "API server error"
