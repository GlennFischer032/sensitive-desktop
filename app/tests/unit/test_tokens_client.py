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
