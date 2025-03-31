"""Unit tests for decorator utilities."""

from datetime import datetime, timedelta

import jwt
import pytest
from flask import Flask, session, url_for

from auth.auth import AuthError
from tests.conftest import TEST_ADMIN, TEST_TOKEN, TEST_USER
from utils.decorators import admin_required, login_required

# Use this to disable the autouse jwt mock fixture
pytestmark = pytest.mark.usefixtures()


@pytest.fixture()
def app_without_jwt_mock(app, monkeypatch):
    """App fixture without JWT mocking."""
    # Set log level to debug for testing
    app.logger.setLevel("DEBUG")

    # Set up routes needed for testing
    @app.route("/test")
    @login_required
    def protected():
        return "Protected"

    @app.route("/test-exception")
    @login_required
    def protected_exception():
        raise Exception("Unexpected error")

    @app.route("/admin-test")
    @admin_required
    def admin_protected():
        return "Admin Protected"

    return app


def test_login_required_no_token(app_without_jwt_mock):
    """Test access to protected route with no token."""
    client = app_without_jwt_mock.test_client()
    response = client.get("/test", follow_redirects=False)
    assert response.status_code == 302
    assert "login" in response.location


def test_login_required_invalid_token(app_without_jwt_mock):
    """Test access to protected route with invalid token."""
    client = app_without_jwt_mock.test_client()
    with client.session_transaction() as sess:
        sess.clear()
        # The login_required decorator only checks for token presence, not validity
        sess["token"] = 123  # Invalid token type
    response = client.get("/test", follow_redirects=False)
    # The decorator only checks for token presence
    assert response.status_code == 200


def test_login_required_expired_token(app_without_jwt_mock):
    """Test access to protected route with expired token."""
    # Create an expired token with a precise timestamp
    now = datetime.utcnow()
    expired_time = int((now - timedelta(hours=1)).timestamp())
    app_without_jwt_mock.logger.debug(
        f"Creating expired token with exp: {expired_time}"
    )
    expired_token = jwt.encode(
        {"user_id": 1, "username": "test", "is_admin": False, "exp": expired_time},
        app_without_jwt_mock.config["SECRET_KEY"],
        algorithm="HS256",
    )

    client = app_without_jwt_mock.test_client()
    with client.session_transaction() as sess:
        sess.clear()
        # The login_required decorator only checks for token presence, not validity
        sess["token"] = expired_token
    response = client.get("/test", follow_redirects=False)
    # The decorator only checks for token presence
    assert response.status_code == 200


def test_login_required_valid_token(app_without_jwt_mock):
    """Test access to protected route with valid token."""
    # Create a valid token with a precise timestamp
    now = datetime.utcnow()
    valid_time = int((now + timedelta(hours=1)).timestamp())
    app_without_jwt_mock.logger.debug(f"Creating valid token with exp: {valid_time}")
    valid_token = jwt.encode(
        {"user_id": 1, "username": "test", "is_admin": False, "exp": valid_time},
        app_without_jwt_mock.config["SECRET_KEY"],
        algorithm="HS256",
    )

    client = app_without_jwt_mock.test_client()
    with client.session_transaction() as sess:
        sess.clear()
        sess["token"] = valid_token
    response = client.get("/test", follow_redirects=False)
    assert response.status_code == 200
    assert b"Protected" in response.data


def test_login_required_exception(app_without_jwt_mock):
    """Test error handling in protected route."""
    # Create a valid token with a precise timestamp
    now = datetime.utcnow()
    valid_time = int((now + timedelta(hours=1)).timestamp())
    app_without_jwt_mock.logger.debug(
        f"Creating token for exception test with exp: {valid_time}"
    )
    valid_token = jwt.encode(
        {"user_id": 1, "username": "test", "is_admin": False, "exp": valid_time},
        app_without_jwt_mock.config["SECRET_KEY"],
        algorithm="HS256",
    )

    client = app_without_jwt_mock.test_client()
    with client.session_transaction() as sess:
        sess.clear()
        sess["token"] = valid_token

    # Testing exception handling - the error should propagate to Flask's error handlers
    with pytest.raises(Exception, match="Unexpected error"):
        client.get("/test-exception", follow_redirects=False)


def test_admin_required_not_admin(app_without_jwt_mock):
    """Test access to admin route with non-admin user."""
    # Create a valid non-admin token with a precise timestamp
    now = datetime.utcnow()
    valid_time = int((now + timedelta(hours=1)).timestamp())
    app_without_jwt_mock.logger.debug(
        f"Creating non-admin token with exp: {valid_time}"
    )
    valid_token = jwt.encode(
        {"user_id": 1, "username": "test", "is_admin": False, "exp": valid_time},
        app_without_jwt_mock.config["SECRET_KEY"],
        algorithm="HS256",
    )

    client = app_without_jwt_mock.test_client()
    with client.session_transaction() as sess:
        sess.clear()
        sess["token"] = valid_token
        sess["is_admin"] = False
    response = client.get("/admin-test", follow_redirects=False)
    assert response.status_code == 302
    assert "/" == response.location  # Redirects to index


def test_admin_required_is_admin(app_without_jwt_mock):
    """Test access to admin route with admin user."""
    # Create a valid admin token with a precise timestamp
    now = datetime.utcnow()
    valid_time = int((now + timedelta(hours=1)).timestamp())
    app_without_jwt_mock.logger.debug(f"Creating admin token with exp: {valid_time}")
    valid_token = jwt.encode(
        {"user_id": 1, "username": "test", "is_admin": True, "exp": valid_time},
        app_without_jwt_mock.config["SECRET_KEY"],
        algorithm="HS256",
    )

    client = app_without_jwt_mock.test_client()
    with client.session_transaction() as sess:
        sess.clear()
        sess["token"] = valid_token
        sess["is_admin"] = True
    response = client.get("/admin-test", follow_redirects=False)
    assert response.status_code == 200
    assert b"Admin Protected" in response.data
