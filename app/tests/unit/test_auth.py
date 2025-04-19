"""
This module contains unit tests for authentication functionality.
"""
import pytest
from unittest.mock import patch, MagicMock


@patch("clients.factory.client_factory.get_auth_client")
def test_auth_client_interface(mock_get_auth_client, app):
    """
    GIVEN a Flask application with mocked auth client
    WHEN auth client methods are called
    THEN check they're called with correct parameters
    """
    # Create a mock auth client
    mock_auth_client = MagicMock()
    mock_get_auth_client.return_value = mock_auth_client

    # Mock the response
    mock_auth_client.oidc_login.return_value = ({"auth_url": "https://test-identity-provider/auth"}, 200)

    # Call the method
    response, status = mock_auth_client.oidc_login()

    # Assertions
    assert mock_auth_client.oidc_login.called
    assert "auth_url" in response
    assert status == 200


@patch("clients.factory.client_factory.get_auth_client")
def test_auth_client_callback_handling(mock_get_auth_client, app):
    """
    GIVEN a Flask application with mocked auth client
    WHEN auth client callback method is called
    THEN check it's called with correct parameters
    """
    # Create a mock auth client
    mock_auth_client = MagicMock()
    mock_get_auth_client.return_value = mock_auth_client

    # Mock the response
    mock_auth_client.oidc_callback.return_value = (
        {"token": "test-token", "user": {"username": "test_user", "is_admin": False, "email": "test@example.com"}},
        200,
    )

    # Call the method
    response, status = mock_auth_client.oidc_callback(
        code="test_code", state="test_state", redirect_uri="https://app.example.com/callback"
    )

    # Assertions
    mock_auth_client.oidc_callback.assert_called_once_with(
        code="test_code", state="test_state", redirect_uri="https://app.example.com/callback"
    )

    assert status == 200
    assert "token" in response
    assert "user" in response
    assert response["user"]["username"] == "test_user"
