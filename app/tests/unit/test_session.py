"""
This module contains unit tests for the session utility module.
"""
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
from http import HTTPStatus

from utils.session import configure_session, SessionConfig


def test_session_config():
    """
    GIVEN the SessionConfig class
    WHEN accessing its attributes
    THEN check they have the correct values
    """
    assert SessionConfig.PERMANENT_SESSION_LIFETIME == timedelta(hours=1)
    assert SessionConfig.SESSION_COOKIE_SECURE is True
    assert SessionConfig.SESSION_COOKIE_HTTPONLY is True
    assert SessionConfig.SESSION_COOKIE_SAMESITE == "Lax"
    assert SessionConfig.SESSION_REFRESH_EACH_REQUEST is True


def test_configure_session(app):
    """
    GIVEN a Flask application
    WHEN configure_session is called
    THEN check the session is configured with correct settings
    """
    # Reset config to ensure test isolation
    app.config.update(
        PERMANENT_SESSION_LIFETIME=None,
        SESSION_COOKIE_SECURE=None,
        SESSION_COOKIE_HTTPONLY=None,
        SESSION_COOKIE_SAMESITE=None,
        SESSION_REFRESH_EACH_REQUEST=None,
    )

    # Configure session
    configure_session(app)

    # Check configuration
    assert app.config["PERMANENT_SESSION_LIFETIME"] == SessionConfig.PERMANENT_SESSION_LIFETIME
    assert app.config["SESSION_COOKIE_SECURE"] == SessionConfig.SESSION_COOKIE_SECURE
    assert app.config["SESSION_COOKIE_HTTPONLY"] == SessionConfig.SESSION_COOKIE_HTTPONLY
    assert app.config["SESSION_COOKIE_SAMESITE"] == SessionConfig.SESSION_COOKIE_SAMESITE
    assert app.config["SESSION_REFRESH_EACH_REQUEST"] == SessionConfig.SESSION_REFRESH_EACH_REQUEST
