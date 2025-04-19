"""
This module contains unit tests for authentication middleware.
"""
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask, session, url_for, redirect, Blueprint
from middleware.auth import token_required, admin_required


@pytest.fixture
def fresh_app():
    """Create a fresh Flask application for middleware tests."""
    app = Flask("middleware_test_app")
    app.config.update({"TESTING": True, "SECRET_KEY": "test_middleware_key"})

    # Create auth blueprint with login route
    auth_bp = Blueprint("auth", __name__)

    @auth_bp.route("/login")
    def login():
        return "Login page"

    # Register the auth blueprint
    app.register_blueprint(auth_bp, url_prefix="/auth")

    return app


@pytest.fixture
def protected_client(fresh_app):
    """Create a test client with protected routes."""

    @fresh_app.route("/protected")
    @token_required
    def protected_route():
        return "This is protected"

    @fresh_app.route("/admin-only")
    @token_required
    @admin_required
    def admin_route():
        return "Admin only"

    return fresh_app.test_client()


@pytest.fixture
def logged_in_protected_client(protected_client, fresh_app):
    """A test client with an active user session."""
    with protected_client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["token"] = "test-token"
        sess["user"] = {"id": "test_user", "name": "Test User", "email": "test@example.com"}
    return protected_client


@pytest.fixture
def admin_protected_client(protected_client, fresh_app):
    """A test client with an active admin session."""
    with protected_client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["token"] = "admin-token"
        sess["user"] = {"id": "admin_user", "name": "Admin User", "email": "admin@example.com"}
        sess["is_admin"] = True
    return protected_client


def test_token_required_redirects_when_not_logged_in(protected_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a route protected by token_required is accessed without login
    THEN check that the user is redirected to the login page
    """
    # Access the protected route without being logged in
    response = protected_client.get("/protected", follow_redirects=False)

    # Should redirect to login
    assert response.status_code == 302
    assert "auth/login" in response.location


def test_token_required_allows_access_when_logged_in(logged_in_protected_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a route protected by token_required is accessed by a logged-in user
    THEN check that access is granted
    """
    # Access the protected route while logged in
    response = logged_in_protected_client.get("/protected")

    # Should allow access
    assert response.status_code == 200
    assert b"This is protected" in response.data


def test_admin_required_redirects_non_admin(logged_in_protected_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a route protected by admin_required is accessed by a non-admin
    THEN check that the user is redirected
    """
    # Access the admin route as a regular user
    response = logged_in_protected_client.get("/admin-only", follow_redirects=False)

    # Should redirect to login with an error message
    assert response.status_code == 302
    assert "auth/login" in response.location


def test_admin_required_allows_admin_access(admin_protected_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a route protected by admin_required is accessed by an admin
    THEN check that access is granted
    """
    # Access the admin route as an admin
    response = admin_protected_client.get("/admin-only")

    # Should allow access
    assert response.status_code == 200
    assert b"Admin only" in response.data


@patch("clients.factory.client_factory.get_tokens_client")
def test_token_required_accepts_auth_header(mock_get_tokens_client, fresh_app):
    """
    GIVEN a Flask application with mocked token client
    WHEN a protected route is accessed with Authorization header
    THEN check that the token is validated and access is granted
    """
    # Create mock token client
    mock_tokens_client = MagicMock()
    mock_get_tokens_client.return_value = mock_tokens_client

    # Mock successful token validation
    mock_tokens_client.api_login.return_value = (
        {"username": "api_user", "is_admin": False, "email": "api@example.com"},
        200,
    )

    # Create a test route with the token_required decorator
    @fresh_app.route("/api-protected")
    @token_required
    def api_protected_route():
        return "API access granted"

    client = fresh_app.test_client()

    # Access the route with an Authorization header
    response = client.get("/api-protected", headers={"Authorization": "Bearer test-api-token"})

    # Check token client was called with correct token
    mock_tokens_client.api_login.assert_called_once_with("test-api-token")

    # Should allow access
    assert response.status_code == 200
    assert b"API access granted" in response.data
