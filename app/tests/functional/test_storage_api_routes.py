"""
This module contains functional tests for the Storage API routes.
"""
import json
from unittest.mock import patch, MagicMock

from flask import url_for


def test_list_pvcs_unauthorized(client):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/api/storage/pvcs' page is requested without authentication
    THEN check the response is valid and redirects to login
    """
    response = client.get("/api/storage/pvcs", follow_redirects=False)
    assert response.status_code == 302
    assert "auth/login" in response.location


def test_list_pvcs_authenticated(logged_in_client):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/api/storage/pvcs' page is requested by an authenticated user
    THEN check the response is valid
    """
    with patch("clients.factory.client_factory.get_storage_client") as mock_client:
        # Setup mock response
        mock_storage_client = MagicMock()
        mock_client.return_value = mock_storage_client
        mock_storage_client.list_storage.return_value = [
            {
                "id": 1,
                "name": "test-pvc",
                "size": "10Gi",
                "status": "Bound",
                "created_at": "2023-01-01T00:00:00",
                "is_public": True,
            }
        ]

        # Make request
        response = logged_in_client.get("/api/storage/pvcs")

        # Check response
        assert response.status_code == 200
        json_data = response.get_json()
        assert "pvcs" in json_data
        assert len(json_data["pvcs"]) == 1
        assert json_data["pvcs"][0]["name"] == "test-pvc"


def test_list_pvcs_error(logged_in_client):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/api/storage/pvcs' endpoint encounters an error
    THEN check the error is handled properly
    """
    with patch("clients.factory.client_factory.get_storage_client") as mock_client:
        # Setup mock to raise error
        mock_storage_client = MagicMock()
        mock_client.return_value = mock_storage_client
        mock_storage_client.list_storage.side_effect = Exception("Test error")

        # Make request
        response = logged_in_client.get("/api/storage/pvcs")

        # Check response
        assert response.status_code == 500
        json_data = response.get_json()
        assert "error" in json_data
        assert "Test error" in json_data["error"]


def test_get_pvc_success(logged_in_client):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/api/storage/pvcs/1' endpoint is requested
    THEN check the PVC is returned
    """
    with patch("clients.factory.client_factory.get_storage_client") as mock_client:
        # Setup mock response
        mock_storage_client = MagicMock()
        mock_client.return_value = mock_storage_client
        mock_storage_client.get_storage.return_value = {
            "id": 1,
            "name": "test-pvc",
            "size": "10Gi",
            "status": "Bound",
            "created_at": "2023-01-01T00:00:00",
            "is_public": True,
        }

        # Make request
        response = logged_in_client.get("/api/storage/pvcs/1")

        # Check response
        assert response.status_code == 200
        json_data = response.get_json()
        assert json_data["id"] == 1
        assert json_data["name"] == "test-pvc"


def test_get_pvc_error(logged_in_client):
    """
    GIVEN a Flask application configured for testing
    WHEN get_pvc encounters an error
    THEN check the error is handled properly
    """
    with patch("clients.factory.client_factory.get_storage_client") as mock_client:
        # Setup mock to raise error
        mock_storage_client = MagicMock()
        mock_client.return_value = mock_storage_client
        mock_storage_client.get_storage.side_effect = Exception("PVC not found")

        # Make request
        response = logged_in_client.get("/api/storage/pvcs/999")

        # Check response
        assert response.status_code == 500
        json_data = response.get_json()
        assert "error" in json_data
        assert "PVC not found" in json_data["error"]


def test_create_pvc_success(admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a new PVC is created
    THEN check it succeeds and returns the right response
    """
    with patch("clients.factory.client_factory.get_storage_client") as mock_client:
        # Setup mock response
        mock_storage_client = MagicMock()
        mock_client.return_value = mock_storage_client
        mock_storage_client.create_storage.return_value = {
            "id": 1,
            "name": "new-pvc",
            "size": "10Gi",
            "status": "Pending",
        }

        # Test data
        pvc_data = {"name": "new-pvc", "size": "10Gi", "storage_class": "standard", "is_public": True}

        # Make request
        response = admin_client.post("/api/storage/pvcs", data=json.dumps(pvc_data), content_type="application/json")

        # Check response
        assert response.status_code == 201
        json_data = response.get_json()
        assert json_data["id"] == 1
        assert json_data["name"] == "new-pvc"

        # Verify correct data was passed to client
        mock_storage_client.create_storage.assert_called_once()


def test_create_pvc_missing_data(admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a PVC is created with missing required data
    THEN check the appropriate error is returned
    """
    # Make request with empty data
    response = admin_client.post("/api/storage/pvcs", data=json.dumps({}), content_type="application/json")

    # Check response
    assert response.status_code == 400
    json_data = response.get_json()
    assert "error" in json_data
    assert "No JSON data provided" in json_data["error"] or "Name and size are required" in json_data["error"]


def test_create_pvc_unauthorized(logged_in_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a non-admin tries to create a PVC
    THEN check access is denied (either by redirect or service unavailable response)
    """
    with patch("flask.session") as mock_session:
        # Make sure session is seen as not admin
        mock_session.get.side_effect = lambda k, *args: False if k == "is_admin" else None

        pvc_data = {"name": "new-pvc", "size": "10Gi"}

        response = logged_in_client.post(
            "/api/storage/pvcs", data=json.dumps(pvc_data), content_type="application/json", follow_redirects=False
        )

        assert response.status_code == 403


def test_get_pvc_access_success(admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN PVC access information is requested
    THEN check it returns the right response
    """
    with patch("clients.factory.client_factory.get_storage_client") as mock_client:
        # Setup mock response
        mock_storage_client = MagicMock()
        mock_client.return_value = mock_storage_client
        mock_storage_client.get_pvc_access.return_value = {"is_public": True, "allowed_users": [1, 2, 3]}

        # Make request
        response = admin_client.get("/api/storage/pvcs/access/1")

        # Check response
        assert response.status_code == 200
        json_data = response.get_json()
        assert json_data["is_public"] is True
        assert len(json_data["allowed_users"]) == 3


def test_get_pvc_access_unauthorized(logged_in_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a non-admin tries to get PVC access information
    THEN check access is denied (either by redirect or service unavailable response)
    """
    with patch("flask.session") as mock_session:
        # Make sure session is seen as not admin
        mock_session.get.side_effect = lambda k, *args: False if k == "is_admin" else None

        response = logged_in_client.get("/api/storage/pvcs/access/1", follow_redirects=False)

        assert response.status_code == 403


def test_update_pvc_access_success(admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN PVC access is updated
    THEN check it succeeds and returns the right response
    """
    with patch("clients.factory.client_factory.get_storage_client") as mock_client:
        # Setup mock response
        mock_storage_client = MagicMock()
        mock_client.return_value = mock_storage_client
        mock_storage_client.update_pvc_access.return_value = {"success": True, "message": "Access updated successfully"}

        # Test data
        access_data = {"is_public": False, "allowed_users": [1, 5]}

        # Make request
        response = admin_client.post(
            "/api/storage/pvcs/access/1", data=json.dumps(access_data), content_type="application/json"
        )

        # Check response
        assert response.status_code == 200
        json_data = response.get_json()
        assert json_data["success"] is True

        # Verify the call was made with the right parameters - note that API splits the parameters
        mock_storage_client.update_pvc_access.assert_called_once()
        args, kwargs = mock_storage_client.update_pvc_access.call_args

        # Check the positional arguments based on the API implementation
        # In api_routes.py the call is:
        # storage_client.update_pvc_access(pvc_id, is_public, allowed_users, token=session["token"])
        assert len(args) == 3
        assert args[0] == 1  # pvc_id
        assert args[1] is False  # is_public
        assert args[2] == [1, 5]  # allowed_users
        assert "token" in kwargs


def test_update_pvc_access_missing_data(admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN PVC access is updated with missing data
    THEN check the appropriate error is returned
    """
    # Make request with empty data
    response = admin_client.post("/api/storage/pvcs/access/1", data="", content_type="application/json")

    # Check response - the error could be 400 (bad request) or 500 (internal server error)
    assert response.status_code in [400, 500]
    json_data = response.get_json()
    assert "error" in json_data


def test_update_pvc_access_unauthorized(logged_in_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a non-admin tries to update PVC access
    THEN check access is denied (either by redirect or service unavailable response)
    """
    with patch("flask.session") as mock_session:
        # Make sure session is seen as not admin
        mock_session.get.side_effect = lambda k, *args: False if k == "is_admin" else None

        access_data = {"is_public": True, "allowed_users": []}

        response = logged_in_client.post(
            "/api/storage/pvcs/access/1",
            data=json.dumps(access_data),
            content_type="application/json",
            follow_redirects=False,
        )

        assert response.status_code == 403


def test_get_pvc_connections_success(admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN PVC connections are requested
    THEN check it returns the right response
    """
    with patch("clients.factory.client_factory.get_storage_client") as mock_client:
        # Setup mock response
        mock_storage_client = MagicMock()
        mock_client.return_value = mock_storage_client
        mock_storage_client.get_pvc_connections.return_value = {
            "connections": [{"id": 1, "name": "Connection 1"}, {"id": 2, "name": "Connection 2"}]
        }

        # Make request
        response = admin_client.get("/api/storage/pvcs/connections/1")

        # Check response
        assert response.status_code == 200
        json_data = response.get_json()
        assert "connections" in json_data
        assert len(json_data["connections"]) == 2


def test_get_pvc_connections_unauthorized(logged_in_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a non-admin tries to get PVC connections
    THEN check access is denied (either by redirect or service unavailable response)
    """
    with patch("flask.session") as mock_session:
        # Make sure session is seen as not admin
        mock_session.get.side_effect = lambda k, *args: False if k == "is_admin" else None

        response = logged_in_client.get("/api/storage/pvcs/connections/1", follow_redirects=False)

        assert response.status_code == 403


def test_delete_pvc_success(admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a PVC is deleted
    THEN check it succeeds and returns the right response
    """
    with patch("clients.factory.client_factory.get_storage_client") as mock_client:
        # Setup mock response
        mock_storage_client = MagicMock()
        mock_client.return_value = mock_storage_client
        mock_storage_client.delete_storage.return_value = {"message": "PVC deleted successfully"}

        # Make request
        response = admin_client.delete("/api/storage/pvcs/test-pvc")

        # Check response
        assert response.status_code == 200
        json_data = response.get_json()
        assert "message" in json_data
        assert json_data["message"] == "PVC deleted successfully"

        # Verify the correct PVC name was passed
        mock_storage_client.delete_storage.assert_called_once()
        call_args, call_kwargs = mock_storage_client.delete_storage.call_args
        assert call_args[0] == "test-pvc"
        assert "token" in call_kwargs


def test_delete_pvc_unauthorized(logged_in_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a non-admin tries to delete a PVC
    THEN check access is denied (either by redirect or service unavailable response)
    """
    with patch("flask.session") as mock_session:
        # Make sure session is seen as not admin
        mock_session.get.side_effect = lambda k, *args: False if k == "is_admin" else None

        response = logged_in_client.delete("/api/storage/pvcs/test-pvc", follow_redirects=False)

        assert response.status_code == 403
