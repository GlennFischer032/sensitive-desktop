"""Test configuration and fixtures."""

import os
import shutil
from typing import Any, Dict
from unittest.mock import patch

import fakeredis
import pytest
import redis
import responses
from flask import Flask, session
from flask.testing import FlaskClient

from app import create_app
from middleware.security import rate_limiter
from tests.config import TestConfig

# Test data
TEST_USER = {"username": "testuser", "password": "testpass", "is_admin": False, "id": 1}
TEST_ADMIN = {"username": "admin", "password": "adminpass", "is_admin": True, "id": 2}
TEST_TOKEN = "test-token-12345"


@pytest.fixture(autouse=True)
def mock_session_setup():
    """Mock the session setup to always provide a valid token in tests.

    This automatically applies to all tests.
    """
    # No need to create session directories as we're now using memory-based sessions
    yield


@pytest.fixture()
def app():
    """Create and configure a new app instance for each test."""
    app = create_app(TestConfig)
    app.config["TESTING"] = True
    app.config["SERVER_NAME"] = "localhost"
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["SESSION_COOKIE_DOMAIN"] = None
    app.config["SKIP_AUTH_FOR_TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    # Ensure session is preserved between requests for testing
    app.config["PRESERVE_CONTEXT_ON_EXCEPTION"] = False

    # Store API URL in test config
    app.config["API_URL"] = "http://test-api:5000"

    # Set up application context
    with app.app_context():
        yield app


@pytest.fixture()
def client(app):
    """Create a test client for the app."""
    app.config["PRESERVE_CONTEXT_ON_EXCEPTION"] = False
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    with app.test_client() as client:
        client.testing = True
        # Enable session handling for test client and preserve between requests
        with client.session_transaction() as sess:
            sess["token"] = TEST_TOKEN
            sess["is_admin"] = TEST_ADMIN["is_admin"]
            sess["username"] = TEST_ADMIN["username"]
            sess["user_id"] = TEST_ADMIN["id"]
            sess["logged_in"] = True
            sess.permanent = True

        # Set to preserve context between requests
        client.preserve_context_on_exception = False
        yield client


@pytest.fixture()
def user_client(app):
    """Create a test client with regular user permissions."""
    with app.test_client() as client:
        client.testing = True
        # Enable session handling for test client
        with client.session_transaction() as sess:
            sess["token"] = TEST_TOKEN
            sess["is_admin"] = TEST_USER["is_admin"]
            sess["username"] = TEST_USER["username"]
            sess["user_id"] = TEST_USER["id"]
            sess.permanent = True
        yield client


@pytest.fixture()
def admin_client(app):
    """Create a test client with admin permissions."""
    with app.test_client() as client:
        client.testing = True
        # Enable session handling for test client
        with client.session_transaction() as sess:
            sess["token"] = TEST_TOKEN
            sess["is_admin"] = TEST_ADMIN["is_admin"]
            sess["username"] = TEST_ADMIN["username"]
            sess["user_id"] = TEST_ADMIN["id"]
            sess.permanent = True
        yield client


@pytest.fixture()
def redis_mock():
    """Mock Redis for rate limiting."""
    redis_mock = fakeredis.FakeRedis()
    with patch.object(rate_limiter, "_get_redis_connection", return_value=redis_mock):
        yield redis_mock


@pytest.fixture()
def responses_mock():
    """Create a mock for external API responses."""
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        yield rsps


@pytest.fixture(autouse=True)
def mock_login_required():
    """Mock authentication decorators to always allow access in tests."""
    import unittest.mock
    import middleware.auth

    # Create a pass-through decorator
    def mock_decorator(f):
        return f

    # Apply the mocks
    with unittest.mock.patch('middleware.auth.login_required', mock_decorator), \
         unittest.mock.patch('app.middleware.auth.login_required', mock_decorator), \
         unittest.mock.patch('middleware.auth.admin_required', mock_decorator), \
         unittest.mock.patch('app.middleware.auth.admin_required', mock_decorator):
        yield


@pytest.fixture(autouse=True)
def mock_redis():
    """Mock Redis client for all tests."""
    fake_redis = fakeredis.FakeStrictRedis()
    with pytest.MonkeyPatch.context() as mp:
        # Mock both Redis and from_url to ensure all Redis connections are mocked
        mp.setattr(redis, "Redis", lambda *args, **kwargs: fake_redis)
        mp.setattr(redis, "from_url", lambda *args, **kwargs: fake_redis)
        mp.setattr(redis, "StrictRedis", lambda *args, **kwargs: fake_redis)
        yield fake_redis


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Reset rate limiter between tests."""
    rate_limiter.requests.clear()
    rate_limiter.default_limits = {
        "1s": (1000000, 1),  # Effectively disable rate limiting for tests
        "1m": (1000000, 60),
        "1h": (1000000, 3600),
    }


@pytest.fixture()
def auth_headers() -> Dict[str, str]:
    """Return mock authentication headers."""
    return {"Authorization": f"Bearer {TEST_TOKEN}"}


@pytest.fixture()
def mock_api_response() -> Dict[str, Any]:
    """Mock API response data."""
    return {
        "token": TEST_TOKEN,
        "username": TEST_USER["username"],
        "is_admin": TEST_USER["is_admin"],
    }


@pytest.fixture()
def mock_api_auth(responses_mock):
    """Mock external API responses."""
    # Add default login response
    responses_mock.add(
        responses.POST,
        "http://test-api:5000/api/auth/login",
        json={
            "token": TEST_TOKEN,
            "username": TEST_USER["username"],
            "is_admin": TEST_USER["is_admin"],
        },
        status=200,
        match=[
            responses.matchers.json_params_matcher(
                {"username": TEST_USER["username"], "password": TEST_USER["password"]}
            )
        ],
    )
    return responses_mock


@pytest.fixture(autouse=True)
def mock_jwt(monkeypatch):
    """Mock JWT token validation."""
    from datetime import datetime, timedelta

    def mock_decode(*args, **kwargs):
        # Create an expiration time 1 hour from now
        exp_time = (datetime.utcnow() + timedelta(hours=1)).timestamp()

        if kwargs.get("options", {}).get("verify_signature", True) is False:
            # For token verification
            return {
                "username": TEST_USER["username"],
                "is_admin": TEST_USER["is_admin"],
                "exp": exp_time,
            }

        # Check if the token is for an admin or regular user based on the first argument
        if args and isinstance(args[0], str) and "admin" in args[0]:
            return {
                "username": TEST_ADMIN["username"],
                "is_admin": TEST_ADMIN["is_admin"],
                "exp": exp_time,
            }
        else:
            return {
                "username": TEST_USER["username"],
                "is_admin": TEST_USER["is_admin"],
                "exp": exp_time,
            }

    monkeypatch.setattr("jwt.decode", mock_decode)
