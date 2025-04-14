"""
Functional tests for the auth API routes.
"""

from http import HTTPStatus
from unittest.mock import MagicMock, patch

from flask import json


@patch("app.clients.factory.client_factory.get_auth_client")
def test_api_refresh_token_success(mock_get_auth_client, logged_in_client):
    """
    GIVEN a Flask application with a logged-in user
    WHEN the API refresh token endpoint is called successfully
    THEN check the response is valid with new token
    """
    # Set up the mock auth client
    mock_auth_client = MagicMock()
    mock_auth_client.refresh_token.return_value = (
        {"token": "refreshed-token", "user": {"username": "test-user", "is_admin": False}},
        HTTPStatus.OK,
    )
    mock_get_auth_client.return_value = mock_auth_client

    # Call API endpoint with JSON headers
    response = logged_in_client.post("/api/auth/refresh", data=json.dumps({}), content_type="application/json")
    data = json.loads(response.data)

    # Verify response
    assert response.status_code == 200
    assert data.get("token") == "refreshed-token"
    assert data.get("user") == {"username": "test-user", "is_admin": False}
    mock_auth_client.refresh_token.assert_called_once()


@patch("app.clients.factory.client_factory.get_auth_client")
def test_api_refresh_token_unauthenticated(mock_get_auth_client, client):
    """
    GIVEN a Flask application with an unauthenticated user
    WHEN the API refresh token endpoint is called
    THEN check that it returns an unauthorized error
    """
    # Set up the mock auth client (should not be called)
    mock_auth_client = MagicMock()
    mock_get_auth_client.return_value = mock_auth_client

    # Call API endpoint with JSON headers
    response = client.post("/api/auth/refresh", data=json.dumps({}), content_type="application/json")

    # Verify response
    assert response.status_code == 302
    assert response.headers["Location"] == "/auth/login"
    mock_auth_client.refresh_token.assert_not_called()


@patch("app.clients.factory.client_factory.get_auth_client")
def test_api_refresh_token_auth_error(mock_get_auth_client, logged_in_client):
    """
    GIVEN a Flask application with a logged-in user
    WHEN the API refresh token endpoint returns an auth error
    THEN check that it returns the error with the correct status code
    """
    # Set up the mock auth client
    mock_auth_client = MagicMock()
    mock_auth_client.refresh_token.return_value = ({"error": "Invalid or expired token"}, HTTPStatus.UNAUTHORIZED)
    mock_get_auth_client.return_value = mock_auth_client

    # Call API endpoint with JSON headers
    response = logged_in_client.post("/api/auth/refresh", data=json.dumps({}), content_type="application/json")
    data = json.loads(response.data)

    # Verify response
    assert response.status_code == 401
    assert "error" in data
    assert data.get("error") == "Invalid or expired token"
    mock_auth_client.refresh_token.assert_called_once()


@patch("app.clients.factory.client_factory.get_auth_client")
def test_api_refresh_token_network_error(mock_get_auth_client, logged_in_client):
    """
    GIVEN a Flask application with a logged-in user
    WHEN the API refresh token endpoint encounters a network error
    THEN check that it returns a service unavailable error
    """
    # Set up the mock auth client
    mock_auth_client = MagicMock()
    mock_auth_client.refresh_token.side_effect = Exception("Network error")
    mock_get_auth_client.return_value = mock_auth_client

    # Call API endpoint with JSON headers
    response = logged_in_client.post("/api/auth/refresh", data=json.dumps({}), content_type="application/json")
    data = json.loads(response.data)

    # Verify response
    assert response.status_code == 503
    assert "error" in data
    assert "Network error" in data.get("error")
    mock_auth_client.refresh_token.assert_called_once()


def test_api_get_status_authenticated(logged_in_client):
    """
    GIVEN a Flask application with a logged-in user
    WHEN the API status endpoint is called
    THEN check that it returns authenticated status
    """
    # Call API endpoint
    response = logged_in_client.get("/api/auth/status")
    data = json.loads(response.data)

    # Verify response
    assert response.status_code == 200
    assert data.get("authenticated") is True
    assert "user" in data
    assert "username" in data["user"]
    assert "is_admin" in data["user"]


def test_api_get_status_unauthenticated(client):
    """
    GIVEN a Flask application with an unauthenticated user
    WHEN the API status endpoint is called
    THEN check that it returns unauthenticated status
    """
    # Call API endpoint
    response = client.get("/api/auth/status")
    data = json.loads(response.data)

    # Verify response
    assert response.status_code == 200
    assert data.get("authenticated") is False
    assert "user" not in data
