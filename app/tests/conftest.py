"""Test configuration and fixtures."""

import os
import shutil
from typing import Any, Dict

import fakeredis
import pytest
import redis
import responses
from flask import Flask, session

from app import create_app
from middleware.security import rate_limiter
from tests.config import TestConfig

# Test data
TEST_USER = {"username": "testuser", "password": "testpass", "is_admin": False}

TEST_ADMIN = {"username": "admin", "password": "adminpass", "is_admin": True}

TEST_TOKEN = "test-token-12345"


@pytest.fixture()
def app():
    """Create and configure a new app instance for each test."""
    app = create_app(TestConfig)
    app.config["TESTING"] = True
    app.config["SERVER_NAME"] = "localhost"
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["SESSION_COOKIE_DOMAIN"] = None

    # Push an application context
    with app.app_context():
        yield app


@pytest.fixture()
def client(app):
    """Create a test client with session handling."""
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["token"] = TEST_TOKEN
            sess["username"] = TEST_USER["username"]
            sess["is_admin"] = TEST_USER["is_admin"]
            sess["logged_in"] = True
            sess.permanent = True
        yield client


@pytest.fixture(autouse=True)
def session_dir():
    """Set up and tear down session directory."""
    os.makedirs(TestConfig.SESSION_FILE_DIR, exist_ok=True)
    yield
    shutil.rmtree(TestConfig.SESSION_FILE_DIR, ignore_errors=True)


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
def responses_mock():
    """Mock external API responses."""
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        yield rsps


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
