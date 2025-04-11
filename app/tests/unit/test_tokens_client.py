"""
Unit tests for the Tokens client.
"""

from unittest.mock import patch

import pytest

from app.clients.base import APIError
from app.clients.tokens import TokensClient


def test_tokens_client_initialization():
    """
    GIVEN a TokensClient class
    WHEN a new TokensClient is created
    THEN check it initializes correctly
    """
    client = TokensClient()
    assert client is not None


@patch("app.clients.base.BaseClient.get")
def test_list_tokens_success(mock_get):
    """
    GIVEN a TokensClient
    WHEN list_tokens() is called
    THEN check it calls the API correctly and returns the response
    """
    # Set up mock
    mock_response = (
        {
            "tokens": [
                {"id": "token1", "name": "Test Token 1", "expires_at": "2023-12-31"},
                {"id": "token2", "name": "Test Token 2", "expires_at": "2024-01-15"},
            ]
        },
        200,
    )
    mock_get.return_value = mock_response

    # Call method
    client = TokensClient()
    tokens_data = client.list_tokens()

    # Verify
    mock_get.assert_called_once()
    args, kwargs = mock_get.call_args
    request = kwargs["request"]
    assert request.endpoint == "/api/tokens"
    assert tokens_data["tokens"][0]["id"] == "token1"
    assert tokens_data["tokens"][1]["name"] == "Test Token 2"


@patch("app.clients.base.BaseClient.get")
def test_list_tokens_error(mock_get):
    """
    GIVEN a TokensClient
    WHEN list_tokens() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_get.side_effect = APIError("Failed to fetch tokens", 500)

    # Call method and verify exception
    client = TokensClient()
    with pytest.raises(APIError):
        client.list_tokens()


@patch("app.clients.base.BaseClient.post")
def test_create_token_minimal(mock_post):
    """
    GIVEN a TokensClient
    WHEN create_token() is called with minimal parameters
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = (
        {
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "id": "new-token-id",
            "name": "Test Token",
            "expires_at": "2023-12-31",
        },
        201,
    )
    mock_post.return_value = mock_response

    # Call method
    client = TokensClient()
    result = client.create_token(name="Test Token")

    # Verify
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    request = kwargs["request"]
    assert request.endpoint == "/api/tokens"
    assert request.data == {"name": "Test Token", "expires_in_days": 30}
    assert "token" in result
    assert result["name"] == "Test Token"


@patch("app.clients.base.BaseClient.post")
def test_create_token_with_all_parameters(mock_post):
    """
    GIVEN a TokensClient
    WHEN create_token() is called with all parameters
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = (
        {
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "id": "new-token-id",
            "name": "Test Token",
            "description": "Token for testing",
            "expires_at": "2023-12-31",
        },
        201,
    )
    mock_post.return_value = mock_response

    # Call method
    client = TokensClient()
    result = client.create_token(name="Test Token", description="Token for testing", expires_in_days=60)

    # Verify
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    request = kwargs["request"]
    assert request.endpoint == "/api/tokens"
    assert request.data == {"name": "Test Token", "description": "Token for testing", "expires_in_days": 60}
    assert result["description"] == "Token for testing"


@patch("app.clients.base.BaseClient.post")
def test_create_token_error(mock_post):
    """
    GIVEN a TokensClient
    WHEN create_token() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_post.side_effect = APIError("Failed to create token", 400)

    # Call method and verify exception
    client = TokensClient()
    with pytest.raises(APIError):
        client.create_token(name="Test Token")


@patch("app.clients.base.BaseClient.delete")
def test_revoke_token_success(mock_delete):
    """
    GIVEN a TokensClient
    WHEN revoke_token() is called
    THEN check it calls the API correctly
    """
    # Set up mock
    mock_response = ({"message": "Token revoked successfully"}, 200)
    mock_delete.return_value = mock_response

    # Call method
    client = TokensClient()
    result = client.revoke_token(token_id="token123")

    # Verify
    mock_delete.assert_called_once()
    args, kwargs = mock_delete.call_args
    request = kwargs["request"]
    assert request.endpoint == "/api/tokens/token123"
    assert result["message"] == "Token revoked successfully"


@patch("app.clients.base.BaseClient.delete")
def test_revoke_token_error(mock_delete):
    """
    GIVEN a TokensClient
    WHEN revoke_token() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_delete.side_effect = APIError("Failed to revoke token", 404)

    # Call method and verify exception
    client = TokensClient()
    with pytest.raises(APIError):
        client.revoke_token(token_id="nonexistent-token")
