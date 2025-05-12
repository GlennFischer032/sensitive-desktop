"""
This module contains functional tests for the tokens API routes.
"""
import json
from unittest.mock import patch, MagicMock, ANY

import pytest
from http import HTTPStatus


def test_api_tokens_unauthorized(client):
    """
    GIVEN a Flask application configured for testing
    WHEN the tokens API endpoint is requested by an unauthenticated user
    THEN check that access is denied (redirects to login)
    """
    response = client.get("/api/tokens/")
    assert response.status_code == 403
    assert "You need to log in to access this page" in response.data.decode("utf-8")


def test_api_tokens_non_admin(logged_in_client):
    """
    GIVEN a Flask application configured for testing
    WHEN the tokens API endpoint is requested by a non-admin user
    THEN check that access is denied (redirects)
    """
    with logged_in_client.session_transaction() as sess:
        sess["is_admin"] = False
        sess["logged_in"] = True
        sess["token"] = "test-token"

    response = logged_in_client.get("/api/tokens/")
    assert response.status_code == 403
    assert "You need administrator privileges" in response.data.decode("utf-8")


@patch("clients.factory.client_factory.get_tokens_client")
def test_api_list_tokens(mock_tokens_client, admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN the tokens API endpoint is requested by an admin user
    THEN check that tokens are returned
    """
    # Setup mock client
    mock_client = MagicMock()
    mock_tokens_client.return_value = mock_client

    # Configure mock to return test tokens
    mock_client.list_tokens.return_value = {
        "tokens": [
            {
                "id": "token1",
                "name": "API Token 1",
                "description": "Test token",
                "created_at": "2023-01-01T12:00:00Z",
                "expires_at": "2024-01-01T12:00:00Z",
                "last_used": None,
                "revoked": False,
            },
            {
                "id": "token2",
                "name": "API Token 2",
                "description": "Another test token",
                "created_at": "2023-02-01T12:00:00Z",
                "expires_at": "2024-02-01T12:00:00Z",
                "last_used": "2023-03-01T12:00:00Z",
                "revoked": True,
                "revoked_at": "2023-04-01T12:00:00Z",
            },
        ]
    }

    # Access tokens API endpoint
    response = admin_client.get("/api/tokens/")

    # Check response
    assert response.status_code == HTTPStatus.OK
    data = json.loads(response.data)
    assert "tokens" in data
    assert len(data["tokens"]) == 2
    assert data["tokens"][0]["id"] == "token1"
    assert data["tokens"][1]["name"] == "API Token 2"

    # Verify the mock was called correctly
    mock_client.list_tokens.assert_called_once_with(token=ANY)


@patch("clients.factory.client_factory.get_tokens_client")
def test_api_create_token_success(mock_tokens_client, admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a new token is created via the API
    THEN check that the token is created successfully
    """
    # Setup mock client
    mock_client = MagicMock()
    mock_tokens_client.return_value = mock_client

    # Configure mock to return a created token
    mock_client.create_token.return_value = {
        "id": "new-token-id",
        "name": "New API Token",
        "token": "abc123.xyz456.789token",
        "created_at": "2023-05-01T12:00:00Z",
        "expires_at": "2023-06-01T12:00:00Z",
    }

    # Token creation data
    token_data = {"name": "New API Token", "description": "Token for testing", "expires_in_days": 30}

    # Create token via API
    response = admin_client.post("/api/tokens/", data=json.dumps(token_data), content_type="application/json")

    # Check response
    assert response.status_code == HTTPStatus.CREATED
    data = json.loads(response.data)
    assert "token" in data
    assert data["token"]["name"] == "New API Token"
    assert "token" in data["token"]  # The actual token value should be included

    # Verify the mock was called with the right parameters
    mock_client.create_token.assert_called_once()
    call_kwargs = mock_client.create_token.call_args[1]
    assert call_kwargs["name"] == "New API Token"
    assert call_kwargs["description"] == "Token for testing"
    assert call_kwargs["expires_in_days"] == 30
    assert "token" in call_kwargs


@patch("clients.factory.client_factory.get_tokens_client")
def test_api_create_token_missing_name(mock_tokens_client, admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a token creation request is made without a name
    THEN check that an error is returned
    """
    # Token data missing name
    token_data = {"description": "Token for testing", "expires_in_days": 30}

    # Attempt to create token
    response = admin_client.post("/api/tokens/", data=json.dumps(token_data), content_type="application/json")

    # Check response
    assert response.status_code == HTTPStatus.BAD_REQUEST
    data = json.loads(response.data)
    assert "error" in data
    assert "Token name is required" in data["error"]


@patch("clients.factory.client_factory.get_tokens_client")
def test_api_create_token_no_json_data(mock_tokens_client, admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a token creation request is made without JSON data
    THEN check that an error is returned
    """
    # Attempt to create token with no data
    response = admin_client.post("/api/tokens/")

    # Check response
    assert response.status_code == 500  # Internal server error due to JSON parsing
    data = json.loads(response.data)
    assert "error" in data


@patch("clients.factory.client_factory.get_tokens_client")
def test_api_create_token_error(mock_tokens_client, admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a token creation request fails on the backend
    THEN check that the error is handled properly
    """
    # Setup mock client to raise an error
    mock_client = MagicMock()
    mock_tokens_client.return_value = mock_client
    mock_client.create_token.side_effect = Exception("Failed to create token")

    # Token creation data
    token_data = {"name": "New API Token", "description": "Token for testing"}

    # Attempt to create token
    response = admin_client.post("/api/tokens/", data=json.dumps(token_data), content_type="application/json")

    # Check response
    assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    data = json.loads(response.data)
    assert "error" in data
    assert "Failed to create token" in data["error"]


@patch("clients.factory.client_factory.get_tokens_client")
def test_api_revoke_token_success(mock_tokens_client, admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a token revocation request is made
    THEN check that the token is revoked successfully
    """
    # Setup mock client
    mock_client = MagicMock()
    mock_tokens_client.return_value = mock_client

    # Token ID to revoke
    token_id = "token1"

    # Revoke token
    response = admin_client.delete(f"/api/tokens/{token_id}")

    # Check response
    assert response.status_code == HTTPStatus.OK
    data = json.loads(response.data)
    assert "message" in data
    assert "revoked successfully" in data["message"]

    # Verify the mock was called correctly
    mock_client.revoke_token.assert_called_once_with(token_id, token=ANY)


@patch("clients.factory.client_factory.get_tokens_client")
def test_api_revoke_token_error(mock_tokens_client, admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a token revocation request fails
    THEN check that the error is handled properly
    """
    # Setup mock client to raise an error
    mock_client = MagicMock()
    mock_tokens_client.return_value = mock_client
    mock_client.revoke_token.side_effect = Exception("Failed to revoke token")

    # Token ID to revoke
    token_id = "token1"

    # Attempt to revoke token
    response = admin_client.delete(f"/api/tokens/{token_id}")

    # Check response
    assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    data = json.loads(response.data)
    assert "error" in data
    assert "Failed to revoke token" in data["error"]
