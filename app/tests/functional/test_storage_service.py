"""
Functional tests for the storage service.
"""

from unittest.mock import MagicMock, patch


def test_view_pvcs_page_authenticated(logged_in_client):
    """
    GIVEN a Flask application with a logged-in user
    WHEN the storage PVCs page is requested
    THEN check the response is valid
    """
    # Mock the storage client to return test data
    with patch("app.clients.factory.client_factory.get_storage_client") as mock_get_client:
        # Set up the mock storage client
        mock_client = MagicMock()
        mock_client.list_storage.return_value = [
            {"id": "pvc1", "name": "volume1", "size": "10Gi", "status": "Bound"},
            {"id": "pvc2", "name": "volume2", "size": "20Gi", "status": "Bound"},
        ]
        mock_get_client.return_value = mock_client

        # Make the request to the storage page
        response = logged_in_client.get("/storage/", follow_redirects=True)

        # Verify the response
        assert response.status_code == 200
        assert b"Storage" in response.data
        assert b"volume1" in response.data
        assert b"volume2" in response.data


def test_view_pvcs_page_unauthenticated(client):
    """
    GIVEN a Flask application with no logged-in user
    WHEN the storage PVCs page is requested
    THEN check the user is redirected to the login page
    """
    response = client.get("/storage/", follow_redirects=False)

    # Verify redirect to login page
    assert response.status_code == 302
    assert "/auth/login" in response.location


def test_view_pvcs_page_as_admin(admin_client):
    """
    GIVEN a Flask application with a logged-in admin
    WHEN the storage PVCs page is requested
    THEN check additional admin controls are displayed
    """
    # Mock the storage client to return test data
    with patch("app.clients.factory.client_factory.get_storage_client") as mock_get_storage_client:
        # Set up the mock storage client
        mock_storage_client = MagicMock()
        mock_storage_client.list_storage.return_value = [
            {"id": "pvc1", "name": "volume1", "size": "10Gi", "status": "Bound", "created_by": "user1"},
            {"id": "pvc2", "name": "volume2", "size": "20Gi", "status": "Bound", "created_by": "user2"},
        ]
        mock_get_storage_client.return_value = mock_storage_client

        # Mock the users client to return test user data
        with patch("app.clients.factory.client_factory.get_users_client") as mock_get_users_client:
            mock_users_client = MagicMock()
            mock_users_client.list_users.return_value = [
                {"id": "user1", "username": "user1"},
                {"id": "user2", "username": "user2"},
            ]
            mock_get_users_client.return_value = mock_users_client

            # Make the request to the storage page
            response = admin_client.get("/storage/", follow_redirects=True)

            # Verify the response
            assert response.status_code == 200
            assert b"Storage" in response.data
            assert b"volume1" in response.data
            assert b"volume2" in response.data

            # Admin should see both users' storage and admin controls
            assert b"user1" in response.data
            assert b"user2" in response.data
            assert b"Create New" in response.data


def test_view_pvcs_page_error(logged_in_client):
    """
    GIVEN a Flask application with a logged-in user
    WHEN the storage PVCs page is requested but an error occurs
    THEN check an error message is displayed
    """
    # Mock the storage client to raise an exception
    with patch("app.clients.factory.client_factory.get_storage_client") as mock_get_client:
        # Set up the mock storage client to raise an exception
        mock_client = MagicMock()
        mock_client.list_storage.side_effect = Exception("Failed to fetch storage PVCs")
        mock_get_client.return_value = mock_client

        # Make the request to the storage page
        response = logged_in_client.get("/storage/", follow_redirects=True)

        # Verify the response
        assert response.status_code == 200
        assert b"Error fetching storage PVCs" in response.data
