"""
Unit tests for the Storage client.
"""

import pytest
from unittest.mock import patch

from app.clients.storage import StorageClient
from app.clients.base import APIError


def test_storage_client_initialization():
    """
    GIVEN a StorageClient class
    WHEN a new StorageClient is created
    THEN check it initializes correctly
    """
    client = StorageClient()
    assert client is not None


@patch("app.clients.base.BaseClient.get")
def test_list_storage_success(mock_get):
    """
    GIVEN a StorageClient
    WHEN list_storage() is called
    THEN check it calls the API correctly and returns the response
    """
    # Set up mock
    mock_response = (
        {
            "pvcs": [
                {"id": "pvc1", "name": "volume1", "size": "10Gi", "status": "Bound"},
                {"id": "pvc2", "name": "volume2", "size": "20Gi", "status": "Bound"},
            ]
        },
        200,
    )
    mock_get.return_value = mock_response

    # Call method
    client = StorageClient()
    volumes = client.list_storage()

    # Verify
    mock_get.assert_called_once()
    assert len(volumes) == 2
    assert volumes[0]["name"] == "volume1"
    assert volumes[1]["size"] == "20Gi"


@patch("app.clients.base.BaseClient.get")
def test_list_storage_error(mock_get):
    """
    GIVEN a StorageClient
    WHEN list_storage() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_get.side_effect = APIError("Failed to fetch storage volumes", 500)

    # Call method and verify exception
    client = StorageClient()
    with pytest.raises(APIError):
        client.list_storage()


@patch("app.clients.base.BaseClient.get")
def test_get_storage_success(mock_get):
    """
    GIVEN a StorageClient
    WHEN get_storage() is called
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = (
        {
            "pvc": {
                "id": "pvc1",
                "name": "volume1",
                "size": "10Gi",
                "status": "Bound",
                "created_by": "user1",
                "created_at": "2023-01-01T00:00:00Z",
            }
        },
        200,
    )
    mock_get.return_value = mock_response

    # Call method
    client = StorageClient()
    volume = client.get_storage(volume_id="pvc1")

    # Verify
    mock_get.assert_called_once()
    assert volume["id"] == "pvc1"
    assert volume["name"] == "volume1"
    assert volume["size"] == "10Gi"
    assert volume["created_by"] == "user1"


@patch("app.clients.base.BaseClient.get")
def test_get_storage_error(mock_get):
    """
    GIVEN a StorageClient
    WHEN get_storage() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_get.side_effect = APIError("Storage volume not found", 404)

    # Call method and verify exception
    client = StorageClient()
    with pytest.raises(APIError):
        client.get_storage(volume_id="nonexistent")


@patch("app.clients.base.BaseClient.post")
def test_create_storage_minimal(mock_post):
    """
    GIVEN a StorageClient
    WHEN create_storage() is called with minimal parameters
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = (
        {"id": "new-pvc", "name": "new-volume", "size": "5Gi", "status": "Pending"},
        201,
    )
    mock_post.return_value = mock_response

    # Call method
    client = StorageClient()
    result = client.create_storage(name="new-volume", size="5Gi")

    # Verify
    mock_post.assert_called_once()
    assert result["name"] == "new-volume"
    assert result["size"] == "5Gi"


@patch("app.clients.base.BaseClient.post")
def test_create_storage_with_options(mock_post):
    """
    GIVEN a StorageClient
    WHEN create_storage() is called with all parameters
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = (
        {
            "id": "new-pvc",
            "name": "shared-volume",
            "size": "15Gi",
            "status": "Pending",
            "is_public": False,
        },
        201,
    )
    mock_post.return_value = mock_response

    # Call method
    client = StorageClient()
    result = client.create_storage(
        name="shared-volume",
        size="15Gi",
        is_public=False,
        allowed_users=["user1", "user2"],
    )

    # Verify
    mock_post.assert_called_once()
    assert result["name"] == "shared-volume"
    assert result["size"] == "15Gi"
    assert result["is_public"] is False


@patch("app.clients.base.BaseClient.post")
def test_create_storage_error(mock_post):
    """
    GIVEN a StorageClient
    WHEN create_storage() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_post.side_effect = APIError("Failed to create storage volume", 400)

    # Call method and verify exception
    client = StorageClient()
    with pytest.raises(APIError):
        client.create_storage(name="new-volume", size="5Gi")


@patch("app.clients.base.BaseClient.delete")
def test_delete_storage_success(mock_delete):
    """
    GIVEN a StorageClient
    WHEN delete_storage() is called
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = ({"status": "Storage volume deleted successfully"}, 200)
    mock_delete.return_value = mock_response

    # Call method
    client = StorageClient()
    result = client.delete_storage(volume_id="pvc1")

    # Verify
    mock_delete.assert_called_once()
    assert result["status"] == "Storage volume deleted successfully"


@patch("app.clients.base.BaseClient.delete")
def test_delete_storage_error(mock_delete):
    """
    GIVEN a StorageClient
    WHEN delete_storage() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_delete.side_effect = APIError("Storage volume not found", 404)

    # Call method and verify exception
    client = StorageClient()
    with pytest.raises(APIError):
        client.delete_storage(volume_id="nonexistent")


@patch("app.clients.base.BaseClient.get")
def test_get_pvc_access_success(mock_get):
    """
    GIVEN a StorageClient
    WHEN get_pvc_access() is called
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = (
        {
            "is_public": False,
            "allowed_users": ["user1", "user2"],
            "pvc_id": 1,
            "name": "private-volume",
        },
        200,
    )
    mock_get.return_value = mock_response

    # Call method
    client = StorageClient()
    access_info = client.get_pvc_access(pvc_id=1)

    # Verify
    mock_get.assert_called_once()
    assert access_info["is_public"] is False
    assert len(access_info["allowed_users"]) == 2
    assert "user1" in access_info["allowed_users"]
    assert access_info["name"] == "private-volume"


@patch("app.clients.base.BaseClient.get")
def test_get_pvc_access_error(mock_get):
    """
    GIVEN a StorageClient
    WHEN get_pvc_access() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_get.side_effect = APIError("PVC access information not found", 404)

    # Call method and verify exception
    client = StorageClient()
    with pytest.raises(APIError):
        client.get_pvc_access(pvc_id=999)


@patch("app.clients.base.BaseClient.post")
def test_update_pvc_access_success(mock_post):
    """
    GIVEN a StorageClient
    WHEN update_pvc_access() is called
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = (
        {
            "is_public": True,
            "allowed_users": [],
            "pvc_id": 1,
            "name": "public-volume",
        },
        200,
    )
    mock_post.return_value = mock_response

    # Call method
    client = StorageClient()
    result = client.update_pvc_access(pvc_id=1, is_public=True, allowed_users=[])

    # Verify
    mock_post.assert_called_once()
    assert result["is_public"] is True
    assert len(result["allowed_users"]) == 0
    assert result["name"] == "public-volume"


@patch("app.clients.base.BaseClient.post")
def test_update_pvc_access_with_users(mock_post):
    """
    GIVEN a StorageClient
    WHEN update_pvc_access() is called with a list of allowed users
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = (
        {
            "is_public": False,
            "allowed_users": ["user1", "user2", "user3"],
            "pvc_id": 1,
            "name": "shared-volume",
        },
        200,
    )
    mock_post.return_value = mock_response

    # Call method
    client = StorageClient()
    result = client.update_pvc_access(pvc_id=1, is_public=False, allowed_users=["user1", "user2", "user3"])

    # Verify
    mock_post.assert_called_once()
    assert result["is_public"] is False
    assert len(result["allowed_users"]) == 3
    assert "user3" in result["allowed_users"]


@patch("app.clients.base.BaseClient.post")
def test_update_pvc_access_error(mock_post):
    """
    GIVEN a StorageClient
    WHEN update_pvc_access() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_post.side_effect = APIError("Failed to update PVC access", 400)

    # Call method and verify exception
    client = StorageClient()
    with pytest.raises(APIError):
        client.update_pvc_access(pvc_id=1, is_public=True, allowed_users=[])


@patch("app.clients.base.BaseClient.get")
def test_get_pvc_connections_success(mock_get):
    """
    GIVEN a StorageClient
    WHEN get_pvc_connections() is called
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = (
        {
            "pvc_id": 1,
            "connections": [
                {"id": "conn1", "name": "connection1", "status": "running"},
                {"id": "conn2", "name": "connection2", "status": "stopped"},
            ],
        },
        200,
    )
    mock_get.return_value = mock_response

    # Call method
    client = StorageClient()
    result = client.get_pvc_connections(pvc_id=1)

    # Verify
    mock_get.assert_called_once()
    assert result["pvc_id"] == 1
    assert len(result["connections"]) == 2
    assert result["connections"][0]["name"] == "connection1"
    assert result["connections"][1]["status"] == "stopped"


@patch("app.clients.base.BaseClient.get")
def test_get_pvc_connections_empty(mock_get):
    """
    GIVEN a StorageClient
    WHEN get_pvc_connections() is called for a PVC with no connections
    THEN check it returns an empty list of connections
    """
    # Set up mock
    mock_response = (
        {
            "pvc_id": 1,
            "connections": [],
        },
        200,
    )
    mock_get.return_value = mock_response

    # Call method
    client = StorageClient()
    result = client.get_pvc_connections(pvc_id=1)

    # Verify
    mock_get.assert_called_once()
    assert result["pvc_id"] == 1
    assert len(result["connections"]) == 0


@patch("app.clients.base.BaseClient.get")
def test_get_pvc_connections_error(mock_get):
    """
    GIVEN a StorageClient
    WHEN get_pvc_connections() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_get.side_effect = APIError("Failed to fetch PVC connections", 404)

    # Call method and verify exception
    client = StorageClient()
    with pytest.raises(APIError):
        client.get_pvc_connections(pvc_id=999)
