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
    connections_bp = Blueprint("connections", __name__)

    @auth_bp.route("/login")
    def login():
        return "Login page"

    @connections_bp.route("/")
    def view_connections():
        return "Connections list"

    # Register the auth blueprint
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(connections_bp, url_prefix="/connections")

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

    assert response.status_code == 302
    assert "connections" in response.location


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


def test_request_validation_middleware(app):
    """
    GIVEN a Flask application
    WHEN a request with incorrect Content-Type is made
    THEN check that validation middleware rejects it
    """
    client = app.test_client()

    # Test POST request without proper JSON Content-Type
    response = client.post("/api/connections", data='{"name": "test"}', headers={"Content-Type": "text/plain"})

    assert response.status_code == 400
    assert "Content-Type must be application/json" in response.get_json()["message"]

    # Test with correct Content-Type
    response = client.post("/api/connections", json={"name": "test"}, headers={"Content-Type": "application/json"})

    # Should not be rejected by middleware (might fail for other reasons but not 400)
    assert response.status_code != 400 or "Content-Type must be application/json" not in response.get_json().get(
        "message", ""
    )


def test_content_length_validation(app):
    """
    GIVEN a Flask application
    WHEN a request with excessive content length is made
    THEN check that it's rejected
    """
    client = app.test_client()

    # Set a very small max content length for testing
    original_max_length = app.config.get("MAX_CONTENT_LENGTH")
    app.config["MAX_CONTENT_LENGTH"] = 10  # Only allow 10 bytes

    # Create a payload larger than the limit
    large_payload = {"data": "x" * 100}

    # Make request with too large payload
    response = client.post("/api/connections", json=large_payload, headers={"Content-Type": "application/json"})

    assert response.status_code == 413  # Request Entity Too Large

    # Restore original setting
    if original_max_length is not None:
        app.config["MAX_CONTENT_LENGTH"] = original_max_length
    else:
        del app.config["MAX_CONTENT_LENGTH"]


def test_swagger_protection_middleware(app):
    """
    GIVEN a Flask application
    WHEN a request to Swagger docs is made
    THEN check that admin protection works correctly
    """
    client = app.test_client()

    # Test access to Swagger docs without being logged in
    response = client.get("/api/docs/")
    assert response.status_code == 302  # Should redirect to login

    # Test non-admin access
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["token"] = "fake-token"
        sess["user"] = {"id": "user", "name": "Test User"}
        sess["is_admin"] = False

    response = client.get("/api/docs/")
    assert response.status_code == 302  # Should redirect to connections

    # Test admin access
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["token"] = "fake-token"
        sess["user"] = {"id": "admin", "name": "Admin User"}
        sess["is_admin"] = True

    response = client.get("/api/docs/")
    assert response.status_code == 200  # Admin should be able to access
