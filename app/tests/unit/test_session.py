"""Unit tests for session management."""

import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import fakeredis
import jwt
import pytest
from flask import Flask, session
from werkzeug.exceptions import BadRequest

from app.auth.auth import is_authenticated, refresh_token
from app.utils.session import (
    SessionConfig,
    configure_session,
    end_session,
    get_session_info,
    session_manager,
    validate_session_token,
)
from app.tests.conftest import TEST_TOKEN, TEST_USER


@pytest.fixture
def app_with_session(app):
    """Create an app with session support for testing."""
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["SESSION_TYPE"] = "filesystem"
    app.config["SESSION_FILE_DIR"] = "/tmp/flask_session_test"
    app.config["SECRET_KEY"] = "test-secret-key"

    # Create a session directory
    import os
    os.makedirs(app.config["SESSION_FILE_DIR"], exist_ok=True)

    return app


def test_session_config():
    """Test session configuration values."""
    assert SessionConfig.PERMANENT_SESSION_LIFETIME == timedelta(hours=1)
    assert SessionConfig.SESSION_COOKIE_SECURE is True
    assert SessionConfig.SESSION_COOKIE_HTTPONLY is True
    assert SessionConfig.SESSION_COOKIE_SAMESITE == "Lax"
    assert SessionConfig.SESSION_REFRESH_EACH_REQUEST is True


def test_configure_session(app_with_session):
    """Test session configuration application."""
    configure_session(app_with_session)

    assert app_with_session.config["PERMANENT_SESSION_LIFETIME"] == SessionConfig.PERMANENT_SESSION_LIFETIME
    assert app_with_session.config["SESSION_COOKIE_SECURE"] == SessionConfig.SESSION_COOKIE_SECURE
    assert app_with_session.config["SESSION_COOKIE_HTTPONLY"] == SessionConfig.SESSION_COOKIE_HTTPONLY
    assert app_with_session.config["SESSION_COOKIE_SAMESITE"] == SessionConfig.SESSION_COOKIE_SAMESITE
    assert app_with_session.config["SESSION_REFRESH_EACH_REQUEST"] == SessionConfig.SESSION_REFRESH_EACH_REQUEST


def test_session_manager_no_auth(app_with_session):
    """Test session manager with no authentication."""

    @session_manager
    def test_route():
        return {"success": True}, 200

    with app_with_session.test_request_context():
        # Ensure not authenticated
        with patch("app.auth.auth.is_authenticated", return_value=False):
            response, status = test_route()
            assert status == 200
            assert response["success"] is True


def test_session_manager_with_auth(app_with_session):
    """Test session manager with authenticated session."""

    @session_manager
    def test_route():
        return {"success": True}, 200

    with app_with_session.test_request_context():
        # Set up authenticated session
        session["token"] = TEST_TOKEN
        session["username"] = TEST_USER["username"]
        session["is_admin"] = TEST_USER["is_admin"]

        # Mock authentication and token refresh
        with patch("app.utils.session.is_authenticated", return_value=True), \
             patch("app.utils.session.refresh_token") as mock_refresh:
            response, status = test_route()

            # Verify response
            assert status == 200
            assert response["success"] is True
            mock_refresh.assert_called_once()


def test_get_session_info_not_authenticated(app_with_session):
    """Test getting session info when not authenticated."""
    with app_with_session.test_request_context():
        # Empty session
        with patch("app.utils.session.is_authenticated", return_value=False):
            info = get_session_info()

            # Verify session info
            assert info["authenticated"] is False
            assert info["expires_in"] is None


def test_get_session_info_authenticated(app_with_session):
    """Test getting session info when authenticated."""
    with app_with_session.test_request_context():
        # Set up authenticated session
        session["token"] = TEST_TOKEN
        session["username"] = TEST_USER["username"]
        session["is_admin"] = TEST_USER["is_admin"]

        with patch("app.utils.session.is_authenticated", return_value=True):
            info = get_session_info()

            # Verify session info
            assert info["authenticated"] is True
            assert info["username"] == TEST_USER["username"]
            assert info["is_admin"] == TEST_USER["is_admin"]
            assert isinstance(info["expires_in"], int)
            assert info["expires_in"] > 0


def test_end_session(app_with_session):
    """Test ending session."""
    with app_with_session.test_request_context():
        # Set up authenticated session
        session["token"] = TEST_TOKEN
        session["username"] = TEST_USER["username"]
        session["is_admin"] = TEST_USER["is_admin"]

        # End the session
        end_session()

        # Verify session is cleared
        assert "token" not in session
        assert "username" not in session
        assert "is_admin" not in session


def test_validate_session_token_not_authenticated(app_with_session):
    """Test token validation when not authenticated."""
    with app_with_session.test_request_context():
        # Empty session
        with patch("app.utils.session.is_authenticated", return_value=False):
            token = validate_session_token()

            # Should return None for unauthenticated session
            assert token is None


def test_validate_session_token_authenticated(app_with_session):
    """Test token validation when authenticated."""
    with app_with_session.test_request_context():
        # Set up authenticated session
        session["token"] = TEST_TOKEN

        # Mock authenticated state
        with patch("app.utils.session.is_authenticated", return_value=True):
            token = validate_session_token()

            # Should return the session token
            assert token == TEST_TOKEN
