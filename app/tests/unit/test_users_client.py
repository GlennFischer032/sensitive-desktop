"""
This module contains unit tests for the UsersClient.
"""
from unittest.mock import patch, MagicMock

import pytest
from clients.users import UsersClient, APIError


def test_users_client_initialization():
    """
    GIVEN the UsersClient class
    WHEN a new instance is created
    THEN check the client is initialized correctly
    """
    client = UsersClient(base_url="http://test-api:5000")

    assert client.base_url == "http://test-api:5000"
    assert client.logger is not None


@patch("clients.base.BaseClient.get")
def test_list_users_success(mock_get):
    """
    GIVEN a UsersClient instance
    WHEN list_users is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {
        "users": [
            {
                "username": "test-user",
                "sub": "test-sub-id",
                "is_admin": False,
                "created_at": "2023-01-01T00:00:00",
            }
        ]
    }
    mock_get.return_value = (mock_response, 200)

    # Create client and call method
    client = UsersClient(base_url="http://test-api:5000")
    result = client.list_users(token="test-auth-token")

    # Check results
    assert result == mock_response["users"]
    assert len(result) == 1
    assert result[0]["username"] == "test-user"

    # Verify the request was correct
    mock_get.assert_called_once()
    request_arg = mock_get.call_args[1]["request"]
    assert request_arg.endpoint == "/api/users/list"
    assert request_arg.token == "test-auth-token"
    assert request_arg.timeout == 10


@patch("clients.base.BaseClient.get")
def test_list_users_error(mock_get):
    """
    GIVEN a UsersClient instance
    WHEN list_users encounters an error
    THEN check it raises the APIError
    """
    # Setup mock to raise APIError
    mock_get.side_effect = APIError("API error occurred", status_code=500)

    # Create client and call method
    client = UsersClient(base_url="http://test-api:5000")

    # Check that APIError is raised
    with pytest.raises(APIError) as exc_info:
        client.list_users(token="test-auth-token")

    assert "API error occurred" in str(exc_info.value)

    # Verify the request was attempted
    mock_get.assert_called_once()


@patch("clients.base.BaseClient.post")
def test_add_user_success(mock_post):
    """
    GIVEN a UsersClient instance
    WHEN add_user is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {
        "message": "User created successfully",
        "user": {
            "username": "new-user",
            "sub": "new-sub-id",
            "is_admin": True,
            "created_at": "2023-01-01T00:00:00",
        },
    }
    mock_post.return_value = (mock_response, 201)

    # Create client and call method
    client = UsersClient(base_url="http://test-api:5000")
    result = client.add_user(username="new-user", sub="new-sub-id", is_admin=True, token="test-auth-token")

    # Check results
    assert result == mock_response
    assert "message" in result
    assert "user" in result
    assert result["user"]["username"] == "new-user"

    # Verify the request was correct
    mock_post.assert_called_once()
    request_arg = mock_post.call_args[1]["request"]
    assert request_arg.endpoint == "/api/users/createuser"
    assert request_arg.token == "test-auth-token"
    assert request_arg.timeout == 10
    assert request_arg.data == {
        "username": "new-user",
        "sub": "new-sub-id",
        "is_admin": True,
    }


@patch("clients.base.BaseClient.post")
def test_add_user_error(mock_post):
    """
    GIVEN a UsersClient instance
    WHEN add_user encounters an error
    THEN check it raises the APIError
    """
    # Setup mock to raise APIError
    mock_post.side_effect = APIError("User already exists", status_code=409)

    # Create client and call method
    client = UsersClient(base_url="http://test-api:5000")

    # Check that APIError is raised
    with pytest.raises(APIError) as exc_info:
        client.add_user(username="existing-user", sub="existing-sub", token="test-auth-token")

    assert "User already exists" in str(exc_info.value)

    # Verify the request was attempted
    mock_post.assert_called_once()


@patch("clients.base.BaseClient.post")
def test_delete_user_success(mock_post):
    """
    GIVEN a UsersClient instance
    WHEN delete_user is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {"message": "User deleted successfully", "username": "user-to-delete"}
    mock_post.return_value = (mock_response, 200)

    # Create client and call method
    client = UsersClient(base_url="http://test-api:5000")
    result = client.delete_user(username="user-to-delete", token="test-auth-token")

    # Check results
    assert result == mock_response
    assert "message" in result
    assert result["message"] == "User deleted successfully"

    # Verify the request was correct
    mock_post.assert_called_once()
    request_arg = mock_post.call_args[1]["request"]
    assert request_arg.endpoint == "/api/users/removeuser"
    assert request_arg.token == "test-auth-token"
    assert request_arg.timeout == 10
    assert request_arg.data == {"username": "user-to-delete"}


@patch("clients.base.BaseClient.post")
def test_delete_user_error(mock_post):
    """
    GIVEN a UsersClient instance
    WHEN delete_user encounters an error
    THEN check it raises the APIError
    """
    # Setup mock to raise APIError
    mock_post.side_effect = APIError("User not found", status_code=404)

    # Create client and call method
    client = UsersClient(base_url="http://test-api:5000")

    # Check that APIError is raised
    with pytest.raises(APIError) as exc_info:
        client.delete_user(username="non-existent-user", token="test-auth-token")

    assert "User not found" in str(exc_info.value)

    # Verify the request was attempted
    mock_post.assert_called_once()


@patch("clients.base.BaseClient.get")
def test_get_user_success(mock_get):
    """
    GIVEN a UsersClient instance
    WHEN get_user is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {
        "user": {
            "username": "test-user",
            "sub": "test-sub-id",
            "is_admin": False,
            "created_at": "2023-01-01T00:00:00",
        }
    }
    mock_get.return_value = (mock_response, 200)

    # Create client and call method
    client = UsersClient(base_url="http://test-api:5000")
    result = client.get_user(username="test-user", token="test-auth-token")

    # Check results
    assert result == mock_response["user"]
    assert result["username"] == "test-user"
    assert result["is_admin"] is False

    # Verify the request was correct
    mock_get.assert_called_once()
    request_arg = mock_get.call_args[1]["request"]
    assert request_arg.endpoint == "/api/users/test-user"
    assert request_arg.token == "test-auth-token"
    assert request_arg.timeout == 10


@patch("clients.base.BaseClient.get")
def test_get_user_error(mock_get):
    """
    GIVEN a UsersClient instance
    WHEN get_user encounters an error
    THEN check it raises the APIError
    """
    # Setup mock to raise APIError
    mock_get.side_effect = APIError("User not found", status_code=404)

    # Create client and call method
    client = UsersClient(base_url="http://test-api:5000")

    # Check that APIError is raised
    with pytest.raises(APIError) as exc_info:
        client.get_user(username="non-existent-user", token="test-auth-token")

    assert "User not found" in str(exc_info.value)

    # Verify the request was attempted
    mock_get.assert_called_once()


@patch("clients.base.BaseClient.get")
def test_verify_user_success(mock_get):
    """
    GIVEN a UsersClient instance
    WHEN verify_user is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {
        "verified": True,
        "user": {
            "username": "verified-user",
            "sub": "valid-sub-id",
            "is_admin": False,
        },
    }
    mock_get.return_value = (mock_response, 200)

    # Create client and call method
    client = UsersClient(base_url="http://test-api:5000")
    result, status_code = client.verify_user(sub="valid-sub-id")

    # Check results
    assert result == mock_response
    assert status_code == 200
    assert result["verified"] is True
    assert result["user"]["username"] == "verified-user"

    # Verify the request was correct
    mock_get.assert_called_once()
    request_arg = mock_get.call_args[1]["request"]
    assert request_arg.endpoint == "/api/users/verify"
    assert request_arg.params == {"sub": "valid-sub-id"}
    assert request_arg.timeout == 5


@patch("clients.base.BaseClient.get")
def test_verify_user_not_found(mock_get):
    """
    GIVEN a UsersClient instance
    WHEN verify_user is called with a sub that doesn't exist
    THEN check it returns the expected response
    """
    # Setup mock response for user not found
    mock_response = {"verified": False, "message": "User not found"}
    mock_get.return_value = (mock_response, 404)

    # Create client and call method
    client = UsersClient(base_url="http://test-api:5000")
    result, status_code = client.verify_user(sub="invalid-sub-id")

    # Check results
    assert result == mock_response
    assert status_code == 404
    assert result["verified"] is False

    # Verify the request was correct
    mock_get.assert_called_once()


@patch("clients.base.BaseClient.get")
def test_verify_user_error(mock_get):
    """
    GIVEN a UsersClient instance
    WHEN verify_user encounters an error
    THEN check it raises the APIError
    """
    # Setup mock to raise APIError
    mock_get.side_effect = APIError("Server error", status_code=500)

    # Create client and call method
    client = UsersClient(base_url="http://test-api:5000")

    # Check that APIError is raised
    with pytest.raises(APIError) as exc_info:
        client.verify_user(sub="some-sub-id")

    assert "Server error" in str(exc_info.value)

    # Verify the request was attempted
    mock_get.assert_called_once()
