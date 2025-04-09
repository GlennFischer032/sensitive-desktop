"""
Unit tests for the Auth client.
"""

import pytest
from unittest.mock import patch
from flask import session

from app.clients.auth import AuthClient
from app.clients.base import APIError


def test_auth_client_initialization():
    """
    GIVEN an AuthClient class
    WHEN a new AuthClient is created
    THEN check it initializes correctly
    """
    auth_client = AuthClient()
    assert auth_client is not None


def test_logout(app):
    """
    GIVEN an AuthClient
    WHEN logout() is called
    THEN check that the session is cleared
    """
    # Set up
    with app.test_request_context():
        # Set some session data
        session["logged_in"] = True
        session["user_id"] = "test-user-id"

        # Call logout
        auth_client = AuthClient()
        auth_client.logout()

        # Verify session is cleared
        assert session.get("logged_in") is None
        assert session.get("user_id") is None


@patch("app.clients.base.BaseClient.post")
def test_oidc_callback_success(mock_post):
    """
    GIVEN an AuthClient
    WHEN oidc_callback() is called with valid parameters
    THEN check it calls the API correctly and returns the response
    """
    # Set up mock
    expected_response = ({"token": "new-token", "user_id": "user123"}, 200)
    mock_post.return_value = expected_response

    # Call method
    auth_client = AuthClient()
    response, status_code = auth_client.oidc_callback(
        code="auth-code", state="state-param", redirect_uri="https://example.com/callback"
    )

    # Verify
    mock_post.assert_called_once()
    request = mock_post.call_args[1]["request"]
    assert request.endpoint == "/api/auth/oidc/callback"
    assert request.data["code"] == "auth-code"
    assert request.data["state"] == "state-param"
    assert request.data["redirect_uri"] == "https://example.com/callback"
    assert response["token"] == "new-token"
    assert status_code == 200


@patch("app.clients.base.BaseClient.post")
def test_oidc_callback_failure(mock_post):
    """
    GIVEN an AuthClient
    WHEN oidc_callback() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_post.side_effect = APIError("OIDC callback failed", 400)

    # Call method and verify exception
    auth_client = AuthClient()
    with pytest.raises(APIError):
        auth_client.oidc_callback(code="invalid-code", state="state-param", redirect_uri="https://example.com/callback")


@patch("app.clients.base.BaseClient.get")
def test_oidc_login_success(mock_get):
    """
    GIVEN an AuthClient
    WHEN oidc_login() is called
    THEN check it calls the API correctly and returns the response
    """
    # Set up mock
    expected_response = ({"auth_url": "https://auth-provider.com/authorize"}, 200)
    mock_get.return_value = expected_response

    # Call method
    auth_client = AuthClient()
    response, status_code = auth_client.oidc_login()

    # Verify
    mock_get.assert_called_once()
    request = mock_get.call_args[1]["request"]
    assert request.endpoint == "/api/auth/oidc/login"
    assert response["auth_url"] == "https://auth-provider.com/authorize"
    assert status_code == 200


@patch("app.clients.base.BaseClient.get")
def test_oidc_login_failure(mock_get):
    """
    GIVEN an AuthClient
    WHEN oidc_login() is called and the API returns an error
    THEN check it raises an APIError
    """
    # Set up mock
    mock_get.side_effect = APIError("OIDC login initiation failed", 500)

    # Call method and verify exception
    auth_client = AuthClient()
    with pytest.raises(APIError):
        auth_client.oidc_login()
