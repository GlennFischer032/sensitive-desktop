"""
This module contains functional tests for the authentication API routes.
"""
import json
from unittest.mock import patch, MagicMock
from http import HTTPStatus

import pytest


def test_auth_status_not_authenticated(client):
    """
    GIVEN a Flask application with an unauthenticated client
    WHEN the auth status endpoint is called
    THEN check that the correct response is returned
    """
    response = client.get("/api/auth/status")

    assert response.status_code == HTTPStatus.OK
    data = json.loads(response.data)
    assert data["authenticated"] is False


def test_auth_status_authenticated(logged_in_client):
    """
    GIVEN a Flask application with an authenticated client
    WHEN the auth status endpoint is called
    THEN check that the correct user data is returned
    """
    # First set up the session data
    with logged_in_client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["token"] = "test-token"
        sess["username"] = "test_user"
        sess["is_admin"] = False
        sess["email"] = "test@example.com"

    response = logged_in_client.get("/api/auth/status")

    assert response.status_code == HTTPStatus.OK
    data = json.loads(response.data)
    assert data["authenticated"] is True
    assert "user" in data
    assert data["user"]["username"] == "test_user"
    assert data["user"]["is_admin"] is False
    assert data["user"]["email"] == "test@example.com"


@patch("clients.factory.client_factory.get_auth_client")
def test_token_refresh_success(mock_auth_client, logged_in_client):
    """
    GIVEN a Flask application with an authenticated client
    WHEN the token refresh endpoint is called
    THEN check that the token is refreshed successfully
    """
    # Set up mock auth client
    mock_client = MagicMock()
    mock_auth_client.return_value = mock_client

    # Configure mock response
    mock_client.refresh_token.return_value = ({"token": "new-test-token"}, HTTPStatus.OK)

    # Set up session data
    with logged_in_client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["token"] = "old-test-token"
        sess["username"] = "test_user"

    # Call the refresh endpoint
    response = logged_in_client.post("/api/auth/refresh")

    # Verify the response
    assert response.status_code == HTTPStatus.OK
    data = json.loads(response.data)
    assert "token" in data

    # Verify the mock was called with the correct token
    mock_client.refresh_token.assert_called_once_with(token="old-test-token")

    # Verify the session was updated with the new token
    with logged_in_client.session_transaction() as sess:
        assert sess["token"] == "new-test-token"


@patch("clients.factory.client_factory.get_auth_client")
def test_token_refresh_unauthorized(mock_auth_client, client):
    """
    GIVEN a Flask application with an unauthenticated client
    WHEN the token refresh endpoint is called
    THEN check that user is redirected to login page
    """
    response = client.post("/api/auth/refresh")
    assert response.status_code == HTTPStatus.FORBIDDEN
    assert "You need to log in to access this page" in response.data.decode("utf-8")


@patch("clients.factory.client_factory.get_auth_client")
def test_token_refresh_error(mock_auth_client, logged_in_client):
    """
    GIVEN a Flask application with an authenticated client
    WHEN the token refresh endpoint fails
    THEN check that an appropriate error is returned and session is cleared
    """
    # Set up mock auth client to return an error
    mock_client = MagicMock()
    mock_auth_client.return_value = mock_client

    # Configure mock to return an error response
    from services.auth.auth import AuthError

    mock_client.refresh_token.side_effect = AuthError("Token expired", status_code=HTTPStatus.UNAUTHORIZED)

    # Set up session data
    with logged_in_client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["token"] = "old-test-token"
        sess["username"] = "test_user"

    # Call the refresh endpoint
    response = logged_in_client.post("/api/auth/refresh")

    # Verify the response
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    data = json.loads(response.data)
    assert "error" in data

    # Verify the session was cleared
    with logged_in_client.session_transaction() as sess:
        assert "token" not in sess
        assert "logged_in" not in sess
