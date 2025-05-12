"""
This module contains functional tests for the users routes.
"""
import json
from unittest.mock import patch, MagicMock

import pytest
from clients.base import APIError


def test_view_users_unauthorized(client):
    """
    GIVEN a Flask application configured for testing
    WHEN the users page is requested by an unauthenticated user
    THEN check that the user is redirected to the login page
    """
    response = client.get("/users/", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.location


def test_view_users_non_admin(logged_in_client):
    """
    GIVEN a Flask application configured for testing
    WHEN the users page is requested by a non-admin user
    THEN check that the user is redirected to connections page
    """
    # Make sure the user is not an admin
    with logged_in_client.session_transaction() as sess:
        sess["is_admin"] = False
        sess["logged_in"] = True
        sess["token"] = "test-token"

    response = logged_in_client.get("/users/", follow_redirects=False)
    assert response.status_code == 403


@patch("clients.factory.client_factory.get_users_client")
def test_view_users_admin_success(mock_users_client, admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN the users page is requested by an admin user
    THEN check that the users page is displayed with users data
    """
    # Setup mock client
    mock_client = MagicMock()
    mock_users_client.return_value = mock_client

    # Configure mock to return test users
    mock_client.list_users.return_value = [
        {"id": 1, "username": "admin", "email": "admin@example.com", "is_admin": True},
        {"id": 2, "username": "user1", "email": "user1@example.com", "is_admin": False},
    ]

    # Access the users page
    response = admin_client.get("/users/")

    # Check response
    assert response.status_code == 200
    assert b"admin@example.com" in response.data
    assert b"user1@example.com" in response.data

    # Verify the mock was called correctly
    mock_client.list_users.assert_called_once()


@patch("clients.factory.client_factory.get_users_client")
def test_view_users_admin_api_error(mock_users_client, admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN the users API call fails with an APIError
    THEN check that the error is handled properly
    """
    # Setup mock client to raise an API error
    mock_client = MagicMock()
    mock_users_client.return_value = mock_client
    mock_client.list_users.side_effect = APIError("Failed to fetch users", 500)

    # Access the users page
    response = admin_client.get("/users/")

    # Check response
    assert response.status_code == 200
    assert b"Failed to fetch users" in response.data
    # Should show an empty users list
    assert b"[]" in response.data or b"No users found" in response.data


@patch("clients.factory.client_factory.get_users_client")
def test_view_users_admin_general_error(mock_users_client, admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN the users API call fails with a general error
    THEN check that the error is handled properly
    """
    # Setup mock client to raise a general error
    mock_client = MagicMock()
    mock_users_client.return_value = mock_client
    mock_client.list_users.side_effect = Exception("General error")

    # Access the users page
    response = admin_client.get("/users/")

    # Check response
    assert response.status_code == 200
    assert b"Error fetching users" in response.data
    # Should show an empty users list
    assert b"[]" in response.data or b"No users found" in response.data


def test_dashboard_unauthorized(client):
    """
    GIVEN a Flask application configured for testing
    WHEN the dashboard is requested by an unauthenticated user
    THEN check that the user is redirected to the login page
    """
    response = client.get("/users/dashboard", follow_redirects=False)

    # There should only be one correct behavior - redirect to login
    assert response.status_code == 302
    assert "/auth/login" in response.location


@patch("clients.factory.client_factory.get_users_client")
def test_dashboard_admin_success(mock_users_client, admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN the dashboard is requested by an admin user
    THEN check that the dashboard is displayed with users data
    """
    # Setup mock client
    mock_client = MagicMock()
    mock_users_client.return_value = mock_client

    # Configure mock to return test users
    mock_client.list_users.return_value = [
        {"id": 1, "username": "admin", "email": "admin@example.com", "is_admin": True},
        {"id": 2, "username": "user1", "email": "user1@example.com", "is_admin": False},
    ]

    # Access the dashboard
    response = admin_client.get("/users/dashboard")

    # Check response
    assert response.status_code == 200
    # Dashboard should contain user data
    assert b"dashboard" in response.data.lower()

    # Verify the mock was called correctly
    mock_client.list_users.assert_called_once()


@patch("clients.factory.client_factory.get_users_client")
def test_dashboard_admin_api_error(mock_users_client, admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN the users API call for dashboard fails with an APIError
    THEN check that the error is handled properly
    """
    # Setup mock client to raise an API error
    mock_client = MagicMock()
    mock_users_client.return_value = mock_client
    mock_client.list_users.side_effect = APIError("Failed to fetch users", 500)

    # Access the dashboard
    response = admin_client.get("/users/dashboard", follow_redirects=True)

    # Check response
    assert response.status_code == 200

    # Error message should be visible in the rendered page
    assert b"Failed to fetch users" in response.data

    # Dashboard should still render successfully
    assert b"Dashboard" in response.data


@patch("clients.factory.client_factory.get_users_client")
def test_dashboard_admin_general_error(mock_users_client, admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN the users API call for dashboard fails with a general error
    THEN check that the error is handled properly
    """
    # Setup mock client to raise a general error
    mock_client = MagicMock()
    mock_users_client.return_value = mock_client
    mock_client.list_users.side_effect = Exception("General error")

    # Access the dashboard
    response = admin_client.get("/users/dashboard", follow_redirects=True)

    # Check response
    assert response.status_code == 200

    # Error message should be visible in the rendered page
    assert b"Error fetching users" in response.data

    # Dashboard should still render successfully
    assert b"Dashboard" in response.data
