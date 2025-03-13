"""Unit tests for auth module functionality."""

from http import HTTPStatus
from unittest.mock import patch

import pytest
import requests
import responses
from flask import Flask, session

from auth.auth import (
    AuthError,
    AuthResponse,
    RateLimitError,
    get_current_user,
    handle_auth_response,
    is_authenticated,
    login,
    logout,
    refresh_token,
)
from tests.config import TestConfig
from tests.conftest import TEST_ADMIN, TEST_TOKEN, TEST_USER


def test_auth_response_validation_success():
    """Test successful validation of auth response data."""
    data = {"token": "test-token", "is_admin": True, "username": "admin"}
    auth_response = AuthResponse(**data)
    assert auth_response.token == "test-token"
    assert auth_response.is_admin is True
    assert auth_response.username == "admin"


def test_auth_response_validation_error():
    """Test validation error for invalid auth response data."""
    with pytest.raises(ValueError):
        AuthResponse(token=123, is_admin="not-bool", username=None)


def test_auth_error():
    """Test AuthError exception."""
    error = AuthError("Test error", HTTPStatus.BAD_REQUEST)
    assert error.message == "Test error"
    assert error.status_code == HTTPStatus.BAD_REQUEST


def test_rate_limit_error():
    """Test RateLimitError exception."""
    error = RateLimitError(60)
    assert error.retry_after == 60
    assert error.status_code == HTTPStatus.TOO_MANY_REQUESTS
    assert "60 seconds" in str(error)


def test_handle_auth_response_success(responses_mock):
    """Test successful handling of auth response."""
    response = requests.Response()
    response.status_code = HTTPStatus.OK
    response._content = (
        b'{"token": "test-token", "is_admin": true, "username": "admin"}'
    )

    data, status = handle_auth_response(response)
    assert status == HTTPStatus.OK
    assert data["token"] == "test-token"
    assert data["is_admin"] is True
    assert data["username"] == "admin"


def test_handle_auth_response_rate_limit(responses_mock):
    """Test handling of rate-limited auth response."""
    response = requests.Response()
    response.status_code = HTTPStatus.TOO_MANY_REQUESTS
    response.headers["Retry-After"] = "30"
    response._content = b'{"error": "Rate limit exceeded"}'

    with pytest.raises(RateLimitError) as exc_info:
        handle_auth_response(response)
    assert exc_info.value.retry_after == 30


def test_handle_auth_response_error(responses_mock):
    """Test handling of error auth response."""
    response = requests.Response()
    response.status_code = HTTPStatus.UNAUTHORIZED
    response._content = b'{"error": "Invalid credentials"}'

    with pytest.raises(AuthError) as exc_info:
        handle_auth_response(response)
    assert exc_info.value.message == "Invalid credentials"
    assert exc_info.value.status_code == HTTPStatus.UNAUTHORIZED


def test_handle_auth_response_request_error(responses_mock):
    """Test handling of request error in auth response."""
    response = requests.Response()
    response.status_code = HTTPStatus.OK
    response._content = b'{"token": "test-token"}'

    with patch(
        "requests.Response.json",
        side_effect=requests.exceptions.RequestException("Connection error"),
    ):
        with pytest.raises(AuthError) as exc_info:
            handle_auth_response(response)
        assert str(exc_info.value) == "Failed to connect to authentication service"


def test_handle_auth_response_validation_error(responses_mock):
    """Test handling of validation error in auth response."""
    response = requests.Response()
    response.status_code = HTTPStatus.OK
    response._content = b'{"invalid": "data"}'  # Missing required fields

    with pytest.raises(AuthError) as exc_info:
        handle_auth_response(response)
    assert str(exc_info.value) == "Invalid response from authentication service"


def test_handle_auth_response_missing_retry_after(responses_mock):
    """Test handling of rate-limited auth response with missing Retry-After header."""
    response = requests.Response()
    response.status_code = HTTPStatus.TOO_MANY_REQUESTS
    response._content = b'{"error": "Rate limit exceeded"}'

    with pytest.raises(RateLimitError) as exc_info:
        handle_auth_response(response)
    assert exc_info.value.retry_after == 60  # Default value


def test_handle_auth_response_non_json(responses_mock):
    """Test handling of invalid JSON response."""
    response = requests.Response()
    response.status_code = HTTPStatus.OK
    response._content = b"Invalid JSON"

    with pytest.raises(AuthError) as exc_info:
        handle_auth_response(response)
    assert str(exc_info.value) == "Failed to connect to authentication service"


def test_login_success(app, responses_mock):
    """Test successful login."""
    responses_mock.add(
        responses.POST,
        "http://test-api:5000/auth/login",
        json={
            "token": TEST_TOKEN,
            "is_admin": TEST_USER["is_admin"],
            "username": TEST_USER["username"],
        },
        status=HTTPStatus.OK,
    )

    with app.test_request_context():
        data, status = login(TEST_USER["username"], TEST_USER["password"])
        assert status == HTTPStatus.OK
        assert data["token"] == TEST_TOKEN
        assert session["token"] == TEST_TOKEN
        assert session["is_admin"] == TEST_USER["is_admin"]
        assert session["username"] == TEST_USER["username"]
        assert session["logged_in"] is True


def test_login_failure(app, responses_mock):
    """Test failed login."""
    responses_mock.add(
        responses.POST,
        "http://test-api:5000/auth/login",
        json={"error": "Invalid credentials"},
        status=HTTPStatus.UNAUTHORIZED,
    )

    with app.test_request_context():
        with pytest.raises(AuthError) as exc_info:
            login("wrong", "credentials")
        assert exc_info.value.message == "Invalid credentials"
        assert exc_info.value.status_code == HTTPStatus.UNAUTHORIZED
        assert "token" not in session


def test_logout(app):
    """Test logout functionality."""
    with app.test_request_context():
        session["token"] = TEST_TOKEN
        session["username"] = TEST_USER["username"]
        session["is_admin"] = TEST_USER["is_admin"]
        session["logged_in"] = True

        logout()
        assert "token" not in session
        assert "username" not in session
        assert "is_admin" not in session
        assert "logged_in" not in session


def test_is_authenticated(app):
    """Test authentication check."""
    with app.test_request_context():
        assert not is_authenticated()

        session["logged_in"] = True
        assert is_authenticated()


def test_get_current_user(app):
    """Test getting current user info."""
    with app.test_request_context():
        assert get_current_user() is None

        session["username"] = TEST_USER["username"]
        session["is_admin"] = TEST_USER["is_admin"]
        session["logged_in"] = True

        user = get_current_user()
        assert user is not None
        assert user["username"] == TEST_USER["username"]
        assert user["is_admin"] == TEST_USER["is_admin"]


def test_refresh_token_success(app, responses_mock):
    """Test successful token refresh."""
    new_token = "new-test-token"
    responses_mock.add(
        responses.POST,
        "http://test-api:5000/auth/refresh",
        json={
            "token": new_token,
            "is_admin": TEST_USER["is_admin"],
            "username": TEST_USER["username"],
        },
        status=HTTPStatus.OK,
        match=[
            responses.matchers.header_matcher(
                {
                    "Authorization": f"Bearer {TEST_TOKEN}",
                    "Content-Type": "application/json",
                }
            )
        ],
    )

    with app.test_request_context():
        session["token"] = TEST_TOKEN
        session["username"] = TEST_USER["username"]
        session["is_admin"] = TEST_USER["is_admin"]
        session["logged_in"] = True

        refresh_token()
        assert session["token"] == new_token


def test_refresh_token_failure(app, responses_mock):
    """Test failed token refresh."""
    responses_mock.add(
        responses.POST,
        "http://test-api:5000/auth/refresh",
        json={"error": "Invalid token"},
        status=HTTPStatus.UNAUTHORIZED,
    )

    with app.test_request_context():
        session["token"] = TEST_TOKEN
        session["username"] = TEST_USER["username"]
        session["is_admin"] = TEST_USER["is_admin"]
        session["logged_in"] = True

        with pytest.raises(AuthError) as exc_info:
            refresh_token()
        assert exc_info.value.message == "Invalid token"
        assert "token" not in session
        assert not is_authenticated()


def test_refresh_token_not_authenticated(app):
    """Test token refresh when not authenticated."""
    with app.test_request_context():
        with pytest.raises(AuthError) as exc_info:
            refresh_token()
        assert exc_info.value.message == "Not authenticated"


def test_login_network_error(app, monkeypatch):
    """Test login with network error."""

    def mock_post(*args, **kwargs):
        raise requests.exceptions.ConnectionError("Network error")

    monkeypatch.setattr("app.auth.auth.requests.post", mock_post)

    with app.test_request_context():
        with pytest.raises(Exception) as exc_info:
            login("testuser", "testpass")
        assert isinstance(exc_info.value, AuthError)
        assert "Network error" in str(exc_info.value)
        assert "token" not in session


def test_refresh_token_network_error(app, monkeypatch):
    """Test token refresh with network error."""

    def mock_post(*args, **kwargs):
        raise requests.exceptions.ConnectionError("Network error")

    monkeypatch.setattr("app.auth.auth.requests.post", mock_post)

    with app.test_request_context():
        session["logged_in"] = True
        session["token"] = "test-token"

        with pytest.raises(Exception) as exc_info:
            refresh_token()
        assert isinstance(exc_info.value, AuthError)
        assert "Network error" in str(exc_info.value)
        assert "token" not in session
        assert not is_authenticated()
