"""
Unit tests for the Users client.
"""

from unittest.mock import patch

import pytest

from app.clients.base import APIError
from app.clients.users import UsersClient


def test_users_client_initialization():
    """
    GIVEN a UsersClient class
    WHEN a new UsersClient is created
    THEN check it initializes correctly
    """
    client = UsersClient()
    assert client is not None


@patch("app.clients.base.BaseClient.get")
def test_list_users_success(mock_get):
    """
    GIVEN a UsersClient
    WHEN list_users() is called
    THEN check it calls the API correctly and returns the response
    """
    # Set up mock
    mock_response = (
        {
            "users": [
                {"id": "user1", "username": "johndoe", "is_admin": False},
                {"id": "user2", "username": "janedoe", "is_admin": True},
            ]
        },
        200,
    )
    mock_get.return_value = mock_response

    # Call method
    client = UsersClient()
    users = client.list_users()

    # Verify
    mock_get.assert_called_once()
    assert len(users) == 2
    assert users[0]["username"] == "johndoe"
    assert users[1]["is_admin"] is True


@patch("app.clients.base.BaseClient.get")
def test_list_users_error(mock_get):
    """
    GIVEN a UsersClient
    WHEN list_users() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_get.side_effect = APIError("Failed to fetch users", 500)

    # Call method and verify exception
    client = UsersClient()
    with pytest.raises(APIError):
        client.list_users()


@patch("app.clients.base.BaseClient.post")
def test_add_user_minimal(mock_post):
    """
    GIVEN a UsersClient
    WHEN add_user() is called with minimal parameters
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = ({"id": "new-user", "username": "newuser", "is_admin": False}, 201)
    mock_post.return_value = mock_response

    # Call method
    client = UsersClient()
    result = client.add_user(username="newuser", sub="sub123")

    # Verify
    mock_post.assert_called_once()
    assert result["username"] == "newuser"
    assert result["is_admin"] is False


@patch("app.clients.base.BaseClient.post")
def test_add_user_with_admin(mock_post):
    """
    GIVEN a UsersClient
    WHEN add_user() is called with admin parameter
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = ({"id": "new-user", "username": "adminuser", "is_admin": True}, 201)
    mock_post.return_value = mock_response

    # Call method
    client = UsersClient()
    result = client.add_user(username="adminuser", sub="sub456", is_admin=True)

    # Verify
    mock_post.assert_called_once()
    assert result["username"] == "adminuser"
    assert result["is_admin"] is True


@patch("app.clients.base.BaseClient.post")
def test_add_user_error(mock_post):
    """
    GIVEN a UsersClient
    WHEN add_user() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_post.side_effect = APIError("Failed to add user", 400)

    # Call method and verify exception
    client = UsersClient()
    with pytest.raises(APIError):
        client.add_user(username="newuser", sub="sub123")


@patch("app.clients.base.BaseClient.post")
def test_delete_user_success(mock_post):
    """
    GIVEN a UsersClient
    WHEN delete_user() is called
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = ({"status": "User deleted successfully"}, 200)
    mock_post.return_value = mock_response

    # Call method
    client = UsersClient()
    result = client.delete_user(username="testuser")

    # Verify
    mock_post.assert_called_once()
    assert result["status"] == "User deleted successfully"


@patch("app.clients.base.BaseClient.post")
def test_delete_user_error(mock_post):
    """
    GIVEN a UsersClient
    WHEN delete_user() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_post.side_effect = APIError("User not found", 404)

    # Call method and verify exception
    client = UsersClient()
    with pytest.raises(APIError):
        client.delete_user(username="nonexistent")


@patch("app.clients.base.BaseClient.get")
def test_get_user_success(mock_get):
    """
    GIVEN a UsersClient
    WHEN get_user() is called
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = (
        {
            "user": {
                "id": "user1",
                "username": "johndoe",
                "is_admin": False,
                "organization": "Example Org",
                "locale": "en-US",
            }
        },
        200,
    )
    mock_get.return_value = mock_response

    # Call method
    client = UsersClient()
    user = client.get_user(username="johndoe")

    # Verify
    mock_get.assert_called_once()
    assert user["id"] == "user1"
    assert user["username"] == "johndoe"
    assert user["organization"] == "Example Org"


@patch("app.clients.base.BaseClient.get")
def test_get_user_error(mock_get):
    """
    GIVEN a UsersClient
    WHEN get_user() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_get.side_effect = APIError("User not found", 404)

    # Call method and verify exception
    client = UsersClient()
    with pytest.raises(APIError):
        client.get_user(username="nonexistent")


@patch("app.clients.base.BaseClient.get")
def test_verify_user_success(mock_get):
    """
    GIVEN a UsersClient
    WHEN verify_user() is called
    THEN check it calls the API correctly and returns the response
    """
    # Set up mock
    mock_response = (
        {"exists": True, "user": {"id": "user1", "username": "johndoe"}},
        200,
    )
    mock_get.return_value = mock_response

    # Call method
    client = UsersClient()
    result, status_code = client.verify_user(sub="sub123")

    # Verify
    mock_get.assert_called_once()
    assert result["exists"] is True
    assert result["user"]["username"] == "johndoe"
    assert status_code == 200


@patch("app.clients.base.BaseClient.get")
def test_verify_user_nonexistent(mock_get):
    """
    GIVEN a UsersClient
    WHEN verify_user() is called for a nonexistent user
    THEN check it returns the correct response
    """
    # Set up mock
    mock_response = ({"exists": False}, 200)
    mock_get.return_value = mock_response

    # Call method
    client = UsersClient()
    result, status_code = client.verify_user(sub="nonexistent-sub")

    # Verify
    mock_get.assert_called_once()
    assert result["exists"] is False
    assert status_code == 200


@patch("app.clients.base.BaseClient.get")
def test_verify_user_error(mock_get):
    """
    GIVEN a UsersClient
    WHEN verify_user() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_get.side_effect = APIError("Verification failed", 500)

    # Call method and verify exception
    client = UsersClient()
    with pytest.raises(APIError):
        client.verify_user(sub="sub123")
