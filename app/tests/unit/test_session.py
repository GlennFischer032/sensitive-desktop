"""Unit tests for session utilities."""

from datetime import datetime, timedelta
from http import HTTPStatus
from unittest.mock import Mock, patch

import pytest
from flask import Flask, session

from auth.auth import AuthError
from tests.conftest import TEST_TOKEN, TEST_USER
from utils.session import (
    SessionConfig,
    configure_session,
    end_session,
    get_session_info,
    session_manager,
    validate_session_token,
)


def test_session_config():
    """Test session configuration constants."""
    assert timedelta(hours=1) == SessionConfig.PERMANENT_SESSION_LIFETIME
    assert SessionConfig.SESSION_COOKIE_SECURE is True
    assert SessionConfig.SESSION_COOKIE_HTTPONLY is True
    assert SessionConfig.SESSION_COOKIE_SAMESITE == "Lax"
    assert SessionConfig.SESSION_REFRESH_EACH_REQUEST is True


def test_configure_session(app: Flask):
    """Test session configuration application."""
    configure_session(app)

    assert (
        app.config["PERMANENT_SESSION_LIFETIME"]
        == SessionConfig.PERMANENT_SESSION_LIFETIME
    )
    assert app.config["SESSION_COOKIE_SECURE"] == SessionConfig.SESSION_COOKIE_SECURE
    assert (
        app.config["SESSION_COOKIE_HTTPONLY"] == SessionConfig.SESSION_COOKIE_HTTPONLY
    )
    assert (
        app.config["SESSION_COOKIE_SAMESITE"] == SessionConfig.SESSION_COOKIE_SAMESITE
    )
    assert (
        app.config["SESSION_REFRESH_EACH_REQUEST"]
        == SessionConfig.SESSION_REFRESH_EACH_REQUEST
    )


def test_session_manager_no_auth(app: Flask):
    """Test session manager with no authentication."""

    @session_manager
    def test_route():
        return {"success": True}, 200

    with app.test_request_context():
        response, status = test_route()
        assert status == 200
        assert response["success"] is True


def test_session_manager_with_auth(app):
    """Test session manager with authenticated session."""

    @session_manager
    def test_route():
        return {"success": True}, HTTPStatus.OK

    with app.test_request_context():
        session["logged_in"] = True
        session["token"] = "test-token"

        with patch("app.utils.session.is_authenticated", return_value=True):
            with patch("requests.post") as mock_post:
                # Mock successful response
                mock_response = Mock()
                mock_response.status_code = HTTPStatus.OK
                mock_response.json.return_value = {
                    "token": "new-token",
                    "username": "testuser",
                    "is_admin": False,
                }
                mock_post.return_value = mock_response

                response, status = test_route()
                assert status == HTTPStatus.OK
                assert response["success"] is True
                mock_post.assert_called_once()
                assert session["token"] == "new-token"


def test_session_manager_refresh_error(app):
    """Test session manager when token refresh fails."""

    @session_manager
    def test_route():
        return {"success": True}, HTTPStatus.OK

    with app.test_request_context():
        session["logged_in"] = True
        session["token"] = "test-token"

        with patch("app.utils.session.is_authenticated", return_value=True):
            with patch("requests.post") as mock_post:
                # Mock error response
                mock_response = Mock()
                mock_response.status_code = HTTPStatus.UNAUTHORIZED
                mock_response.json.return_value = {"error": "Token expired"}
                mock_post.return_value = mock_response

                response, status = test_route()
                assert status == HTTPStatus.UNAUTHORIZED
                assert response["error"] == "Session expired"
                assert response["message"] == "Please log in again"
                assert "logged_in" not in session
                assert "token" not in session


def test_session_manager_error(app: Flask):
    """Test session manager error handling."""

    @session_manager
    def test_route():
        raise ValueError("Test error")

    with app.test_request_context():
        response, status = test_route()
        assert status == HTTPStatus.INTERNAL_SERVER_ERROR
        assert response["error"] == "Session error"
        assert "Test error" in response["message"]


def test_get_session_info_no_auth(app: Flask):
    """Test getting session info without authentication."""
    with app.test_request_context():
        info = get_session_info()
        assert info["authenticated"] is False
        assert info["expires_in"] is None


def test_get_session_info_with_auth(app: Flask):
    """Test getting session info with authentication."""
    with app.test_request_context():
        session["token"] = TEST_TOKEN
        session["username"] = TEST_USER["username"]
        session["is_admin"] = TEST_USER["is_admin"]
        session["logged_in"] = True

        info = get_session_info()
        assert info["authenticated"] is True
        assert info["username"] == TEST_USER["username"]
        assert info["is_admin"] == TEST_USER["is_admin"]
        assert isinstance(info["expires_in"], int)
        assert info["expires_in"] <= 3600  # 1 hour in seconds


def test_end_session(app: Flask):
    """Test ending session."""
    with app.test_request_context():
        session["token"] = TEST_TOKEN
        session["username"] = TEST_USER["username"]
        session["is_admin"] = TEST_USER["is_admin"]
        session["logged_in"] = True

        end_session()
        assert not session


def test_validate_session_token_no_auth(app: Flask):
    """Test token validation without authentication."""
    with app.test_request_context():
        token = validate_session_token()
        assert token is None


def test_validate_session_token_with_auth(app: Flask):
    """Test token validation with authentication."""
    with app.test_request_context():
        session["token"] = TEST_TOKEN
        session["username"] = TEST_USER["username"]
        session["is_admin"] = TEST_USER["is_admin"]
        session["logged_in"] = True

        token = validate_session_token()
        assert token == TEST_TOKEN


def test_validate_session_token_missing(app: Flask):
    """Test token validation with missing token."""
    with app.test_request_context():
        session["logged_in"] = True  # Authenticated but no token

        token = validate_session_token()
        assert token is None
        assert not session  # Session should be cleared


def test_session_manager_no_auth(app: Flask):
    """Test session manager when not authenticated."""

    @session_manager
    def test_route():
        return {"success": True}, HTTPStatus.OK

    with app.test_request_context():
        response, status = test_route()
        assert status == HTTPStatus.OK
        assert response["success"] is True


def test_get_session_info_not_authenticated(app: Flask):
    """Test getting session info when not authenticated."""
    with app.test_request_context():
        info = get_session_info()
        assert info["authenticated"] is False
        assert info["expires_in"] is None


def test_get_session_info_authenticated(app: Flask):
    """Test getting session info when authenticated."""
    with app.test_request_context():
        session["logged_in"] = True
        session["username"] = "testuser"
        session["is_admin"] = True

        with patch("app.utils.session.is_authenticated", return_value=True):
            info = get_session_info()
            assert info["authenticated"] is True
            assert info["username"] == "testuser"
            assert info["is_admin"] is True
            assert isinstance(info["expires_in"], int)
            assert info["expires_in"] > 0


def test_end_session(app: Flask):
    """Test ending session."""
    with app.test_request_context():
        session["logged_in"] = True
        session["username"] = "testuser"

        end_session()
        assert "logged_in" not in session
        assert "username" not in session


def test_end_session_error(app: Flask):
    """Test ending session with error."""
    with app.test_request_context():
        with patch.object(session, "clear", side_effect=Exception("Test error")):
            with pytest.raises(Exception) as exc_info:
                end_session()
            assert str(exc_info.value) == "Test error"


def test_validate_session_token_not_authenticated(app: Flask):
    """Test token validation when not authenticated."""
    with app.test_request_context():
        assert validate_session_token() is None


def test_validate_session_token_no_token(app: Flask):
    """Test token validation when token is missing."""
    with app.test_request_context():
        with patch("app.utils.session.is_authenticated", return_value=True):
            assert validate_session_token() is None
            assert "logged_in" not in session


def test_validate_session_token_success(app: Flask):
    """Test successful token validation."""
    with app.test_request_context():
        session["logged_in"] = True  # Set session as logged in
        session["token"] = "test-token"
        with patch("app.utils.session.is_authenticated", return_value=True):
            assert validate_session_token() == "test-token"
