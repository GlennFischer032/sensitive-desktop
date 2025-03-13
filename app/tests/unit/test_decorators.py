"""Unit tests for decorator utilities."""

from datetime import datetime, timedelta

import jwt
import pytest
from flask import Flask, session, url_for

from auth.auth import AuthError
from tests.conftest import TEST_ADMIN, TEST_TOKEN, TEST_USER
from utils.decorators import admin_required, login_required

pytestmark = pytest.mark.usefixtures()  # Disable autouse fixtures


@pytest.fixture()
def app_without_jwt_mock(app, monkeypatch):
    """App fixture without JWT mocking."""
    # Remove the JWT mock if it exists
    monkeypatch.undo()
    # Set log level to debug for testing
    app.logger.setLevel("DEBUG")
    return app


def test_login_required_no_token(app_without_jwt_mock):
    """Test access to protected route with no token."""

    @app_without_jwt_mock.route("/test")
    @login_required
    def protected():
        return "Protected"

    client = app_without_jwt_mock.test_client()
    response = client.get("/test", follow_redirects=False)
    assert response.status_code == 302
    assert "login" in response.location


def test_login_required_invalid_token(app_without_jwt_mock):
    """Test access to protected route with invalid token."""

    @app_without_jwt_mock.route("/test")
    @login_required
    def protected():
        return "Protected"

    client = app_without_jwt_mock.test_client()
    with client.session_transaction() as sess:
        sess.clear()
        sess["token"] = 123  # Invalid token type (not a string)
    response = client.get("/test", follow_redirects=False)
    assert response.status_code == 302
    assert "login" in response.location


def test_login_required_expired_token(app_without_jwt_mock):
    """Test access to protected route with expired token."""

    @app_without_jwt_mock.route("/test")
    @login_required
    def protected():
        return "Protected"

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
        sess["token"] = expired_token
    response = client.get("/test", follow_redirects=False)
    assert response.status_code == 302
    assert "login" in response.location


def test_login_required_valid_token(app_without_jwt_mock):
    """Test access to protected route with valid token."""

    @app_without_jwt_mock.route("/test")
    @login_required
    def protected():
        return "Protected"

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

    @app_without_jwt_mock.route("/test")
    @login_required
    def protected():
        raise Exception("Unexpected error")

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
    response = client.get("/test", follow_redirects=False)
    assert response.status_code == 302
    assert "login" in response.location


def test_admin_required_not_admin(app_without_jwt_mock):
    """Test access to admin route with non-admin user."""

    @app_without_jwt_mock.route("/admin-test")
    @admin_required
    def admin_protected():
        return "Admin Protected"

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
    assert response.status_code == 403


def test_admin_required_is_admin(app_without_jwt_mock):
    """Test access to admin route with admin user."""

    @app_without_jwt_mock.route("/admin-test")
    @admin_required
    def admin_protected():
        return "Admin Protected"

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
