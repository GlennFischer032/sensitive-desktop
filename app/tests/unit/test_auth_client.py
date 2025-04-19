"""
This module contains unit tests for the AuthClient class.
"""
import pytest
from unittest.mock import patch, MagicMock

from clients.auth import AuthClient
from clients.base import APIError, ClientRequest


def test_auth_client_init():
    """
    GIVEN AuthClient class
    WHEN a new instance is created
    THEN check it is initialized correctly
    """
    client = AuthClient(base_url="http://test-api:5000")

    assert client.base_url == "http://test-api:5000"
    assert client.logger is not None


@patch("clients.base.BaseClient.post")
def test_auth_client_oidc_callback_success(mock_post):
    """
    GIVEN an AuthClient instance
    WHEN the oidc_callback method is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    expected_response = ({"token": "test-token", "user": {"username": "test_user"}}, 200)
    mock_post.return_value = expected_response

    # Create client and call method
    client = AuthClient(base_url="http://test-api:5000")
    response, status = client.oidc_callback(
        code="test-code", state="test-state", redirect_uri="https://app.example.com/callback"
    )

    # Check results
    assert response["token"] == "test-token"
    assert response["user"]["username"] == "test_user"
    assert status == 200

    # Verify the request was correct
    mock_post.assert_called_once()
    request_arg = mock_post.call_args[1]["request"]
    assert isinstance(request_arg, ClientRequest)
    assert request_arg.endpoint == "/api/auth/oidc/callback"
    assert request_arg.data["code"] == "test-code"
    assert request_arg.data["state"] == "test-state"
    assert request_arg.data["redirect_uri"] == "https://app.example.com/callback"
    assert request_arg.timeout == 10


@patch("clients.base.BaseClient.post")
def test_auth_client_oidc_callback_error(mock_post):
    """
    GIVEN an AuthClient instance
    WHEN oidc_callback encounters an error
    THEN check it propagates the APIError
    """
    # Setup mock to raise APIError
    api_error = APIError("API error occurred", status_code=500)
    mock_post.side_effect = api_error

    # Create client and check error handling
    client = AuthClient(base_url="http://test-api:5000")

    with pytest.raises(APIError) as exc_info:
        client.oidc_callback(code="test-code", state="test-state", redirect_uri="https://app.example.com/callback")

    assert exc_info.value == api_error


@patch("clients.base.BaseClient.get")
def test_auth_client_oidc_login_success(mock_get):
    """
    GIVEN an AuthClient instance
    WHEN the oidc_login method is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    expected_response = ({"authorization_url": "https://identity-provider.com/auth"}, 200)
    mock_get.return_value = expected_response

    # Create client and call method
    client = AuthClient(base_url="http://test-api:5000")
    response, status = client.oidc_login()

    # Check results
    assert response["authorization_url"] == "https://identity-provider.com/auth"
    assert status == 200

    # Verify the request was correct
    mock_get.assert_called_once()
    request_arg = mock_get.call_args[1]["request"]
    assert isinstance(request_arg, ClientRequest)
    assert request_arg.endpoint == "/api/auth/oidc/login"
    assert request_arg.timeout == 5


@patch("clients.base.BaseClient.get")
def test_auth_client_oidc_login_error(mock_get):
    """
    GIVEN an AuthClient instance
    WHEN oidc_login encounters an error
    THEN check it propagates the APIError
    """
    # Setup mock to raise APIError
    api_error = APIError("API error occurred", status_code=500)
    mock_get.side_effect = api_error

    # Create client and check error handling
    client = AuthClient(base_url="http://test-api:5000")

    with pytest.raises(APIError) as exc_info:
        client.oidc_login()

    assert exc_info.value == api_error


@patch("clients.base.BaseClient.post")
def test_auth_client_refresh_token_success(mock_post):
    """
    GIVEN an AuthClient instance
    WHEN the refresh_token method is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    expected_response = ({"token": "refreshed-token"}, 200)
    mock_post.return_value = expected_response

    # Create client and call method
    client = AuthClient(base_url="http://test-api:5000")
    response, status = client.refresh_token(token="old-token")

    # Check results
    assert response["token"] == "refreshed-token"
    assert status == 200

    # Verify the request was correct
    mock_post.assert_called_once()
    request_arg = mock_post.call_args[1]["request"]
    assert isinstance(request_arg, ClientRequest)
    assert request_arg.endpoint == "/api/auth/refresh"
    assert request_arg.token == "old-token"
    assert request_arg.timeout == 5


@patch("clients.base.BaseClient.post")
def test_auth_client_refresh_token_error(mock_post):
    """
    GIVEN an AuthClient instance
    WHEN refresh_token encounters an error
    THEN check it propagates the APIError
    """
    # Setup mock to raise APIError
    api_error = APIError("Token expired", status_code=401)
    mock_post.side_effect = api_error

    # Create client and check error handling
    client = AuthClient(base_url="http://test-api:5000")

    with pytest.raises(APIError) as exc_info:
        client.refresh_token(token="old-token")

    assert exc_info.value == api_error
