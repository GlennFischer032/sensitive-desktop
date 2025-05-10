"""
This module contains unit tests for the TokensClient.
"""
from unittest.mock import patch, MagicMock

import pytest
from clients.tokens import TokensClient, APIError


def test_tokens_client_initialization():
    """
    GIVEN the TokensClient class
    WHEN a new instance is created
    THEN check the client is initialized correctly
    """
    client = TokensClient(base_url="http://test-api:5000")

    assert client.base_url == "http://test-api:5000"
    assert client.logger is not None


@patch("clients.base.BaseClient.get")
def test_list_tokens_success(mock_get):
    """
    GIVEN a TokensClient instance
    WHEN list_tokens is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {
        "tokens": [
            {
                "token_id": "test-token-1",
                "name": "Test Token 1",
                "description": "A test token",
                "created_at": "2023-01-01T00:00:00",
                "expires_at": "2024-01-01T00:00:00",
                "created_by": "admin",
            }
        ]
    }
    mock_get.return_value = (mock_response, 200)

    # Create client and call method
    client = TokensClient(base_url="http://test-api:5000")
    result = client.list_tokens(token="test-auth-token")

    # Check results
    assert result == mock_response
    assert "tokens" in result
    assert len(result["tokens"]) == 1
    assert result["tokens"][0]["token_id"] == "test-token-1"

    # Verify the request was correct
    mock_get.assert_called_once()
    request_arg = mock_get.call_args[1]["request"]
    assert request_arg.endpoint == "/api/tokens"
    assert request_arg.token == "test-auth-token"
    assert request_arg.timeout == 10


@patch("clients.base.BaseClient.get")
def test_list_tokens_error(mock_get):
    """
    GIVEN a TokensClient instance
    WHEN list_tokens encounters an error
    THEN check it raises the APIError
    """
    # Setup mock to raise APIError
    mock_get.side_effect = APIError("API error occurred", status_code=500)

    # Create client and call method
    client = TokensClient(base_url="http://test-api:5000")

    # Check that APIError is raised
    with pytest.raises(APIError) as exc_info:
        client.list_tokens(token="test-auth-token")

    assert "API error occurred" in str(exc_info.value)

    # Verify the request was attempted
    mock_get.assert_called_once()


@patch("clients.base.BaseClient.post")
def test_create_token_success(mock_post):
    """
    GIVEN a TokensClient instance
    WHEN create_token is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {
        "message": "Token created successfully",
        "token": {
            "token_id": "new-token-id",
            "name": "New API Token",
            "description": "Token for testing",
            "created_at": "2023-01-01T00:00:00",
            "expires_at": "2023-02-01T00:00:00",
            "created_by": "test-user",
        },
        "jwt": "generated.jwt.token",
    }
    mock_post.return_value = (mock_response, 201)

    # Create client and call method
    client = TokensClient(base_url="http://test-api:5000")
    result = client.create_token(
        name="New API Token", description="Token for testing", expires_in_days=31, token="test-auth-token"
    )

    # Check results
    assert result == mock_response
    assert "message" in result
    assert "token" in result
    assert "jwt" in result
    assert result["token"]["name"] == "New API Token"

    # Verify the request was correct
    mock_post.assert_called_once()
    request_arg = mock_post.call_args[1]["request"]
    assert request_arg.endpoint == "/api/tokens"
    assert request_arg.token == "test-auth-token"
    assert request_arg.timeout == 10
    assert request_arg.data == {
        "name": "New API Token",
        "description": "Token for testing",
        "expires_in_days": 31,
    }


@patch("clients.base.BaseClient.post")
def test_create_token_without_description(mock_post):
    """
    GIVEN a TokensClient instance
    WHEN create_token is called without a description
    THEN check the request is formatted correctly
    """
    # Setup mock response
    mock_response = {
        "message": "Token created successfully",
        "token": {
            "token_id": "new-token-id",
            "name": "New API Token",
            "created_at": "2023-01-01T00:00:00",
            "expires_at": "2023-01-31T00:00:00",
            "created_by": "test-user",
        },
        "jwt": "generated.jwt.token",
    }
    mock_post.return_value = (mock_response, 201)

    # Create client and call method
    client = TokensClient(base_url="http://test-api:5000")
    result = client.create_token(name="New API Token", expires_in_days=30, token="test-auth-token")

    # Check results
    assert result == mock_response

    # Verify the request was correct and doesn't include description
    mock_post.assert_called_once()
    request_arg = mock_post.call_args[1]["request"]
    assert request_arg.data == {
        "name": "New API Token",
        "expires_in_days": 30,
    }
    assert "description" not in request_arg.data


@patch("clients.base.BaseClient.post")
def test_create_token_error(mock_post):
    """
    GIVEN a TokensClient instance
    WHEN create_token encounters an error
    THEN check it raises the APIError
    """
    # Setup mock to raise APIError
    mock_post.side_effect = APIError("Invalid token parameters", status_code=400)

    # Create client and call method
    client = TokensClient(base_url="http://test-api:5000")

    # Check that APIError is raised
    with pytest.raises(APIError) as exc_info:
        client.create_token(name="Invalid Token", expires_in_days=-1, token="test-auth-token")

    assert "Invalid token parameters" in str(exc_info.value)

    # Verify the request was attempted
    mock_post.assert_called_once()


@patch("clients.base.BaseClient.delete")
def test_revoke_token_success(mock_delete):
    """
    GIVEN a TokensClient instance
    WHEN revoke_token is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {"message": "Token revoked successfully", "token_id": "token-to-revoke"}
    mock_delete.return_value = (mock_response, 200)

    # Create client and call method
    client = TokensClient(base_url="http://test-api:5000")
    result = client.revoke_token(token_id="token-to-revoke", token="test-auth-token")

    # Check results
    assert result == mock_response
    assert "message" in result
    assert result["message"] == "Token revoked successfully"

    # Verify the request was correct
    mock_delete.assert_called_once()
    request_arg = mock_delete.call_args[1]["request"]
    assert request_arg.endpoint == "/api/tokens/token-to-revoke"
    assert request_arg.token == "test-auth-token"
    assert request_arg.timeout == 10


@patch("clients.base.BaseClient.delete")
def test_revoke_token_error(mock_delete):
    """
    GIVEN a TokensClient instance
    WHEN revoke_token encounters an error
    THEN check it raises the APIError
    """
    # Setup mock to raise APIError
    mock_delete.side_effect = APIError("Token not found", status_code=404)

    # Create client and call method
    client = TokensClient(base_url="http://test-api:5000")

    # Check that APIError is raised
    with pytest.raises(APIError) as exc_info:
        client.revoke_token(token_id="non-existent-token", token="test-auth-token")

    assert "Token not found" in str(exc_info.value)

    # Verify the request was attempted
    mock_delete.assert_called_once()


@patch("clients.base.BaseClient.post")
def test_api_login_success(mock_post):
    """
    GIVEN a TokensClient instance
    WHEN api_login is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {"username": "api-user", "is_admin": True, "email": "api-user@example.com"}
    mock_post.return_value = (mock_response, 200)

    # Create client and call method
    client = TokensClient(base_url="http://test-api:5000")
    result, status_code = client.api_login(token="valid-api-token")

    # Check results
    assert result == mock_response
    assert status_code == 200
    assert result["username"] == "api-user"
    assert result["is_admin"] is True

    # Verify the request was correct
    mock_post.assert_called_once()
    request_arg = mock_post.call_args[1]["request"]
    assert request_arg.endpoint == "/api/tokens/api-login"
    assert request_arg.token == "valid-api-token"
    assert request_arg.data == {"token": "valid-api-token"}
    assert request_arg.timeout == 5


@patch("clients.base.BaseClient.post")
def test_api_login_unauthorized(mock_post):
    """
    GIVEN a TokensClient instance
    WHEN api_login is called with an invalid token
    THEN check it returns the expected response
    """
    # Setup mock response for unauthorized
    mock_response = {"error": "Invalid or expired token", "message": "Authentication failed"}
    mock_post.return_value = (mock_response, 401)

    # Create client and call method
    client = TokensClient(base_url="http://test-api:5000")
    result, status_code = client.api_login(token="invalid-api-token")

    # Check results
    assert result == mock_response
    assert status_code == 401
    assert "error" in result

    # Verify the request was correct
    mock_post.assert_called_once()


@patch("clients.base.BaseClient.post")
def test_api_login_error(mock_post):
    """
    GIVEN a TokensClient instance
    WHEN api_login encounters an error
    THEN check it raises the APIError
    """
    # Setup mock to raise APIError
    mock_post.side_effect = APIError("Server error", status_code=500)

    # Create client and call method
    client = TokensClient(base_url="http://test-api:5000")

    # Check that APIError is raised
    with pytest.raises(APIError) as exc_info:
        client.api_login(token="some-api-token")

    assert "Server error" in str(exc_info.value)

    # Verify the request was attempted
    mock_post.assert_called_once()
