"""
This module contains functional tests for the storage routes.
"""
from unittest.mock import patch, MagicMock

import pytest
from clients.base import APIError


def test_view_pvcs_unauthorized(client):
    """
    GIVEN a Flask application configured for testing
    WHEN the storage PVCs page is requested by an unauthenticated user
    THEN check that the user is redirected to the login page
    """
    response = client.get("/storage/", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.location


@patch("clients.factory.client_factory.get_storage_client")
def test_view_pvcs_authenticated_success(mock_storage_client, logged_in_client):
    """
    GIVEN a Flask application configured for testing
    WHEN the storage PVCs page is requested by an authenticated user
    THEN check that the PVCs page is displayed with PVCs data
    """
    # Setup mock client
    mock_client = MagicMock()
    mock_storage_client.return_value = mock_client

    # Configure mock to return test PVCs
    mock_client.list_storage.return_value = [
        {
            "name": "pvc-1",
            "size": "10Gi",
            "status": "Bound",
            "created_at": "2023-01-01T12:00:00Z",
            "access_mode": "ReadWriteOnce",
        },
        {
            "name": "pvc-2",
            "size": "20Gi",
            "status": "Bound",
            "created_at": "2023-01-02T12:00:00Z",
            "access_mode": "ReadWriteMany",
        },
    ]

    # Access the PVCs page
    response = logged_in_client.get("/storage/")

    # Check response
    assert response.status_code == 200
    assert b"pvc-1" in response.data
    assert b"pvc-2" in response.data
    assert b"10Gi" in response.data
    assert b"20Gi" in response.data

    # Verify the mock was called correctly
    mock_client.list_storage.assert_called_once()


@patch("clients.factory.client_factory.get_storage_client")
@patch("clients.factory.client_factory.get_users_client")
def test_view_pvcs_admin_with_users(mock_users_client, mock_storage_client, admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN the storage PVCs page is requested by an admin user
    THEN check that the PVCs page includes users data for admin functions
    """
    # Setup mock storage client
    mock_storage = MagicMock()
    mock_storage_client.return_value = mock_storage

    # Configure mock to return test PVCs
    mock_storage.list_storage.return_value = [
        {
            "name": "pvc-1",
            "size": "10Gi",
            "status": "Bound",
            "created_at": "2023-01-01T12:00:00Z",
            "access_mode": "ReadWriteOnce",
        }
    ]

    # Setup mock users client
    mock_users = MagicMock()
    mock_users_client.return_value = mock_users

    # Configure mock to return test users
    mock_users.list_users.return_value = [
        {"id": 1, "username": "admin", "email": "admin@example.com", "is_admin": True},
        {"id": 2, "username": "user1", "email": "user1@example.com", "is_admin": False},
    ]

    # Access the PVCs page as admin
    response = admin_client.get("/storage/")

    # Check response
    assert response.status_code == 200
    assert b"pvc-1" in response.data

    # Admin should see user data for permission management
    # Check for usernames instead of emails since that's what the template displays
    assert b"admin" in response.data or b"user1" in response.data

    # Verify the mocks were called correctly
    mock_storage.list_storage.assert_called_once()
    mock_users.list_users.assert_called_once()


@patch("clients.factory.client_factory.get_storage_client")
def test_view_pvcs_api_error(mock_storage_client, logged_in_client):
    """
    GIVEN a Flask application configured for testing
    WHEN the storage API call fails with an APIError
    THEN check that the error is handled properly
    """
    # Setup mock client to raise an API error
    mock_client = MagicMock()
    mock_storage_client.return_value = mock_client
    mock_client.list_storage.side_effect = APIError("Failed to fetch PVCs", 500)

    # Access the PVCs page
    response = logged_in_client.get("/storage/", follow_redirects=True)

    # Check response
    assert response.status_code == 200

    # Error message should be in the response content
    assert b"Error fetching storage PVCs" in response.data

    # Should render the empty state for PVCs
    assert (
        b"No storage PVCs" in response.data
        or b"No storage PVCs found" in response.data
        or b"No storage PVCs are available" in response.data
    )


@patch("clients.factory.client_factory.get_storage_client")
def test_view_pvcs_general_error(mock_storage_client, logged_in_client):
    """
    GIVEN a Flask application configured for testing
    WHEN the storage API call fails with a general error
    THEN check that the error is handled properly
    """
    # Setup mock client to raise a general error
    mock_client = MagicMock()
    mock_storage_client.return_value = mock_client
    mock_client.list_storage.side_effect = Exception("General error")

    # Access the PVCs page
    response = logged_in_client.get("/storage/", follow_redirects=True)

    # Check response
    assert response.status_code == 200

    # Error message should be in the response content
    assert b"Error fetching storage PVCs" in response.data

    # Should render the empty state for PVCs
    assert (
        b"No storage PVCs" in response.data
        or b"No storage PVCs found" in response.data
        or b"No storage PVCs are available" in response.data
    )
