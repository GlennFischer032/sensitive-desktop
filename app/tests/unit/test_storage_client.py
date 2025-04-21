"""
This module contains unit tests for the StorageClient.
"""
from unittest.mock import patch, MagicMock

import pytest
from clients.storage import StorageClient, APIError


def test_storage_client_initialization():
    """
    GIVEN the StorageClient class
    WHEN a new instance is created
    THEN check the client is initialized correctly
    """
    client = StorageClient(base_url="http://test-api:5000")

    assert client.base_url == "http://test-api:5000"
    assert client.logger is not None


@patch("clients.base.BaseClient.get")
def test_list_storage_success(mock_get):
    """
    GIVEN a StorageClient instance
    WHEN list_storage is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {
        "pvcs": [
            {
                "id": 1,
                "name": "test-volume",
                "size": "10Gi",
                "status": "Bound",
                "created_at": "2023-01-01T00:00:00",
                "created_by": "admin",
                "is_public": True,
            }
        ]
    }
    mock_get.return_value = (mock_response, 200)

    # Create client and call method
    client = StorageClient(base_url="http://test-api:5000")
    result = client.list_storage(token="test-auth-token")

    # Check results
    assert result == mock_response.get("pvcs", [])
    assert len(result) == 1
    assert result[0]["name"] == "test-volume"
    assert result[0]["size"] == "10Gi"

    # Verify the request was correct
    mock_get.assert_called_once()
    request_arg = mock_get.call_args[1]["request"]
    assert request_arg.endpoint == "/api/storage-pvcs/list"
    assert request_arg.token == "test-auth-token"


@patch("clients.base.BaseClient.get")
def test_list_storage_error(mock_get):
    """
    GIVEN a StorageClient instance
    WHEN list_storage encounters an error
    THEN check it raises the APIError
    """
    # Setup mock to raise APIError
    mock_get.side_effect = APIError("API error occurred", status_code=500)

    # Create client and call method
    client = StorageClient(base_url="http://test-api:5000")

    # Check that APIError is raised
    with pytest.raises(APIError) as exc_info:
        client.list_storage(token="test-auth-token")

    assert "API error occurred" in str(exc_info.value)

    # Verify the request was attempted
    mock_get.assert_called_once()


@patch("clients.base.BaseClient.get")
def test_get_storage_success(mock_get):
    """
    GIVEN a StorageClient instance
    WHEN get_storage is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {
        "pvc": {
            "id": 1,
            "name": "test-volume",
            "size": "10Gi",
            "status": "Bound",
            "created_at": "2023-01-01T00:00:00",
            "created_by": "admin",
            "is_public": True,
        }
    }
    mock_get.return_value = (mock_response, 200)

    # Create client and call method
    client = StorageClient(base_url="http://test-api:5000")
    result = client.get_storage(volume_id="1", token="test-auth-token")

    # Check results
    assert result == mock_response.get("pvc", {})
    assert result["name"] == "test-volume"
    assert result["size"] == "10Gi"

    # Verify the request was correct
    mock_get.assert_called_once()
    request_arg = mock_get.call_args[1]["request"]
    assert request_arg.endpoint == "/api/storage-pvcs/1"
    assert request_arg.token == "test-auth-token"


@patch("clients.base.BaseClient.post")
def test_create_storage_success(mock_post):
    """
    GIVEN a StorageClient instance
    WHEN create_storage is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {
        "id": 1,
        "name": "new-volume",
        "size": "20Gi",
        "status": "Creating",
    }
    mock_post.return_value = (mock_response, 201)

    # Create client and call method
    client = StorageClient(base_url="http://test-api:5000")
    result = client.create_storage(
        name="new-volume", size="20Gi", is_public=True, allowed_users=["user1", "user2"], token="test-auth-token"
    )

    # Check results
    assert result == mock_response
    assert result["name"] == "new-volume"
    assert result["size"] == "20Gi"

    # Verify the request was correct
    mock_post.assert_called_once()
    request_arg = mock_post.call_args[1]["request"]
    assert request_arg.endpoint == "/api/storage-pvcs/create"
    assert request_arg.token == "test-auth-token"
    assert request_arg.timeout == 30
    assert request_arg.data == {
        "name": "new-volume",
        "size": "20Gi",
        "is_public": True,
        "allowed_users": ["user1", "user2"],
    }


@patch("clients.base.BaseClient.delete")
def test_delete_storage_success(mock_delete):
    """
    GIVEN a StorageClient instance
    WHEN delete_storage is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {"message": "Storage volume deleted successfully"}
    mock_delete.return_value = (mock_response, 200)

    # Create client and call method
    client = StorageClient(base_url="http://test-api:5000")
    result = client.delete_storage(volume_id="1", token="test-auth-token")

    # Check results
    assert result == mock_response
    assert "message" in result

    # Verify the request was correct
    mock_delete.assert_called_once()
    request_arg = mock_delete.call_args[1]["request"]
    assert request_arg.endpoint == "/api/storage-pvcs/1"
    assert request_arg.token == "test-auth-token"
    assert request_arg.timeout == 30


@patch("clients.base.BaseClient.get")
def test_get_pvc_access_success(mock_get):
    """
    GIVEN a StorageClient instance
    WHEN get_pvc_access is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {"is_public": False, "allowed_users": ["user1", "user2"]}
    mock_get.return_value = (mock_response, 200)

    # Create client and call method
    client = StorageClient(base_url="http://test-api:5000")
    result = client.get_pvc_access(pvc_id=1, token="test-auth-token")

    # Check results
    assert result == mock_response
    assert result["is_public"] is False
    assert "user1" in result["allowed_users"]

    # Verify the request was correct
    mock_get.assert_called_once()
    request_arg = mock_get.call_args[1]["request"]
    assert request_arg.endpoint == "/api/storage-pvcs/1/access"
    assert request_arg.token == "test-auth-token"
    assert request_arg.timeout == 10


@patch("clients.base.BaseClient.post")
def test_update_pvc_access_success(mock_post):
    """
    GIVEN a StorageClient instance
    WHEN update_pvc_access is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {"message": "Access settings updated successfully", "is_public": True, "allowed_users": []}
    mock_post.return_value = (mock_response, 200)

    # Create client and call method
    client = StorageClient(base_url="http://test-api:5000")
    result = client.update_pvc_access(pvc_id=1, is_public=True, allowed_users=[], token="test-auth-token")

    # Check results
    assert result == mock_response
    assert "message" in result
    assert result["is_public"] is True

    # Verify the request was correct
    mock_post.assert_called_once()
    request_arg = mock_post.call_args[1]["request"]
    assert request_arg.endpoint == "/api/storage-pvcs/1/access"
    assert request_arg.token == "test-auth-token"
    assert request_arg.timeout == 30
    assert request_arg.data == {"is_public": True, "allowed_users": []}


@patch("clients.base.BaseClient.get")
def test_get_pvc_connections_success(mock_get):
    """
    GIVEN a StorageClient instance
    WHEN get_pvc_connections is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {"connections": [{"id": 1, "type": "notebook", "name": "test-notebook", "owner": "admin"}]}
    mock_get.return_value = (mock_response, 200)

    # Create client and call method
    client = StorageClient(base_url="http://test-api:5000")
    result = client.get_pvc_connections(pvc_id=1, token="test-auth-token")

    # Check results
    assert result == mock_response
    assert "connections" in result
    assert len(result["connections"]) == 1

    # Verify the request was correct
    mock_get.assert_called_once()
    request_arg = mock_get.call_args[1]["request"]
    assert request_arg.endpoint == "/api/storage-pvcs/connections/1"
    assert request_arg.token == "test-auth-token"
    assert request_arg.timeout == 10
