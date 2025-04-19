"""
This module contains functional tests for authentication endpoints.
"""
import pytest
from unittest.mock import patch, MagicMock
from flask import url_for, session


def test_login_page_renders(client):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/login' endpoint is requested (GET)
    THEN check that the response is valid and login page is rendered
    """
    response = client.get("/auth/login")
    assert response.status_code == 200
    assert b"<title>" in response.data
    assert b"Login" in response.data


def test_logout_redirects_to_login(client):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/logout' endpoint is accessed
    THEN check that the user is redirected to the login page
    """
    response = client.get("/auth/logout", follow_redirects=False)
    assert response.status_code == 302
    assert "/auth/login" in response.location


@patch("clients.factory.client_factory.get_auth_client")
def test_oidc_login_redirects_to_provider(mock_get_auth_client, client):
    """
    GIVEN a Flask application with mocked auth client
    WHEN the '/oidc/login' endpoint is accessed
    THEN check that it redirects to the OIDC provider
    """
    # Create a mock auth client
    mock_auth_client = MagicMock()
    mock_get_auth_client.return_value = mock_auth_client

    # Mock the response
    mock_auth_client.oidc_login.return_value = ({"auth_url": "https://test-provider/auth"}, 200)

    # Access the endpoint
    response = client.get("/auth/oidc/login", follow_redirects=False)

    # Check that auth client was called
    mock_auth_client.oidc_login.assert_called_once()

    # Check redirect
    assert response.status_code == 302
    assert response.location == "https://test-provider/auth"


@patch("clients.factory.client_factory.get_auth_client")
def test_oidc_callback_success(mock_get_auth_client, client):
    """
    GIVEN a Flask application with mocked auth client
    WHEN the '/oidc/callback' endpoint is accessed with valid params
    THEN check that the user is logged in and redirected appropriately
    """
    # Create a mock auth client
    mock_auth_client = MagicMock()
    mock_get_auth_client.return_value = mock_auth_client

    # Mock the response for a successful regular user login
    mock_auth_client.oidc_callback.return_value = (
        {"token": "test-jwt-token", "user": {"username": "test_user", "is_admin": False, "email": "test@example.com"}},
        200,
    )

    # Access the callback endpoint with required params
    response = client.get("/auth/oidc/callback?code=test_code&state=test_state", follow_redirects=False)

    # Check that auth client was called with correct params
    mock_auth_client.oidc_callback.assert_called_once()
    call_args = mock_auth_client.oidc_callback.call_args[1]
    assert call_args["code"] == "test_code"
    assert call_args["state"] == "test_state"

    # Check redirect to connections for regular user
    assert response.status_code == 302
    assert "/connections/" in response.location


@patch("clients.factory.client_factory.get_auth_client")
def test_oidc_callback_admin_redirects_to_dashboard(mock_get_auth_client, client):
    """
    GIVEN a Flask application with mocked auth client
    WHEN the '/oidc/callback' endpoint is accessed for an admin user
    THEN check that the admin is redirected to the dashboard
    """
    # Create a mock auth client
    mock_auth_client = MagicMock()
    mock_get_auth_client.return_value = mock_auth_client

    # Mock the response for a successful admin login
    mock_auth_client.oidc_callback.return_value = (
        {
            "token": "admin-jwt-token",
            "user": {"username": "admin_user", "is_admin": True, "email": "admin@example.com"},
        },
        200,
    )

    # Access the callback endpoint with required params
    response = client.get("/auth/oidc/callback?code=admin_code&state=test_state", follow_redirects=False)

    # Check redirect to admin dashboard
    assert response.status_code == 302
    assert "/users/dashboard" in response.location


@patch("clients.factory.client_factory.get_auth_client")
def test_oidc_callback_error_handling(mock_get_auth_client, client):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/oidc/callback' endpoint is accessed with error params
    THEN check that error is handled and user is redirected to login
    """
    # Access the callback endpoint with error params
    response = client.get(
        "/auth/oidc/callback?error=access_denied&error_description=User+cancelled", follow_redirects=False
    )

    # Should redirect to login page
    assert response.status_code == 302
    assert "/auth/login" in response.location

    # Auth client should not be called for error case
    mock_get_auth_client.assert_not_called()
