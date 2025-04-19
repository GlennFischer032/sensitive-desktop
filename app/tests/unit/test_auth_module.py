"""
This module contains unit tests for the authentication module functionality.
"""
import pytest
from unittest.mock import MagicMock
from http import HTTPStatus

from services.auth.auth import AuthError, RateLimitError, handle_auth_response


def test_auth_error_initialization():
    """
    GIVEN AuthError class
    WHEN a new instance is created
    THEN check it initializes with correct attributes
    """
    error = AuthError("Authentication failed")

    assert error.message == "Authentication failed"
    assert error.status_code == HTTPStatus.UNAUTHORIZED
    assert str(error) == "Authentication failed"

    custom_error = AuthError("Custom error", HTTPStatus.FORBIDDEN)
    assert custom_error.message == "Custom error"
    assert custom_error.status_code == HTTPStatus.FORBIDDEN


def test_rate_limit_error_initialization():
    """
    GIVEN RateLimitError class
    WHEN a new instance is created
    THEN check it initializes with correct attributes
    """
    error = RateLimitError(30)

    assert error.retry_after == 30
    assert error.status_code == HTTPStatus.TOO_MANY_REQUESTS
    assert "Rate limit exceeded" in error.message
    assert "30 seconds" in error.message


def test_handle_auth_response_success():
    """
    GIVEN a successful response from auth API
    WHEN handle_auth_response is called
    THEN check it returns the expected data and status code
    """
    mock_response = MagicMock()
    mock_response.status_code = HTTPStatus.OK
    mock_response.json.return_value = {"token": "test-token", "user": {"username": "test_user"}}

    data, status = handle_auth_response(mock_response)

    assert status == HTTPStatus.OK
    assert data["token"] == "test-token"
    assert data["user"]["username"] == "test_user"


def test_handle_auth_response_rate_limit():
    """
    GIVEN a rate-limited response from auth API
    WHEN handle_auth_response is called
    THEN check it raises RateLimitError
    """
    mock_response = MagicMock()
    mock_response.status_code = HTTPStatus.TOO_MANY_REQUESTS
    mock_response.headers = {"Retry-After": "45"}

    with pytest.raises(RateLimitError) as exc_info:
        handle_auth_response(mock_response)

    assert exc_info.value.retry_after == 45
    assert "45 seconds" in str(exc_info.value)


def test_handle_auth_response_error():
    """
    GIVEN an error response from auth API
    WHEN handle_auth_response is called
    THEN check it raises AuthError with correct message and status
    """
    mock_response = MagicMock()
    mock_response.status_code = HTTPStatus.FORBIDDEN
    mock_response.json.return_value = {"error": "Access denied"}

    with pytest.raises(AuthError) as exc_info:
        handle_auth_response(mock_response)

    assert exc_info.value.message == "Access denied"
    assert exc_info.value.status_code == HTTPStatus.FORBIDDEN
