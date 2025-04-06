"""Unit tests for authentication decorators."""

import time
from datetime import datetime, timedelta
from unittest.mock import patch

import jwt
import pytest
from flask import Flask, session, url_for

from app.middleware.auth import admin_required, login_required
from app.tests.conftest import TEST_ADMIN, TEST_TOKEN, TEST_USER


def test_login_required_valid_token(app, client):
    """Test access to protected route with valid token."""
    # Define a test route using the decorator
    @app.route("/test-protected")
    @login_required
    def test_protected_route():
        return "Protected Content", 200

    # With our client fixture, token is already in session
    response = client.get("/test-protected")

    # Should be able to access the protected route
    assert response.status_code == 200
    assert b"Protected Content" in response.data


def test_login_required_no_token(app):
    """Test access to protected route without token."""
    # Define a test route using the decorator
    @app.route("/test-protected")
    @login_required
    def test_protected_route():
        return "Protected Content", 200

    # Disable the test mode skipping auth
    app.config["SKIP_AUTH_FOR_TESTING"] = False

    # Use a client without a token in session
    client = app.test_client()
    response = client.get("/test-protected")

    # Should be redirected to login page
    assert response.status_code == 302
    assert "/auth/login" in response.headers.get("Location", "")


def test_admin_required_is_admin(app, admin_client):
    """Test access to admin-only route with admin privileges."""
    # Define a test route using the decorator
    @app.route("/test-admin")
    @admin_required
    def test_admin_route():
        return "Admin Content", 200

    # Access the route as admin
    response = admin_client.get("/test-admin")

    # Should be able to access the admin route
    assert response.status_code == 200
    assert b"Admin Content" in response.data


def test_admin_required_not_admin(app, user_client):
    """Test access to admin-only route without admin privileges."""
    # Define a test route using the decorator
    @app.route("/test-admin")
    @admin_required
    def test_admin_route():
        return "Admin Content", 200

    # Disable the test mode skipping auth
    app.config["SKIP_AUTH_FOR_TESTING"] = False

    # Access the route as a regular user
    response = user_client.get("/test-admin")

    # Should be redirected to home
    assert response.status_code == 302
    assert "/" in response.headers.get("Location", "")
