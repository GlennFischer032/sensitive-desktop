"""pytest configuration and fixtures."""

import pytest
import fakeredis
from unittest.mock import patch

from app import create_app
from app.clients.redis_client import RedisClient
from app.tests.config import TestConfig


@pytest.fixture(scope="function")
def app():
    """Create and configure a Flask application for testing."""
    # Create the app with TestConfig
    fake_redis = fakeredis.FakeRedis()

    # Use patch to replace redis.from_url with fake redis
    with patch("redis.from_url", return_value=fake_redis):
        # Create app with TestConfig
        app = create_app(TestConfig)

        # Ensure the TestConfig settings are applied
        app.config.update(
            {
                "TESTING": True,
                "WTF_CSRF_ENABLED": False,
            }
        )

        # Disable rate limiting during tests by removing the check_rate_limit from before_request
        app.before_request_funcs[None] = [
            f for f in app.before_request_funcs.get(None, []) if f.__name__ != "check_rate_limit"
        ]

        # Set up a dummy rate limiter that always returns not limited
        with patch("app.middleware.security.rate_limiter.is_rate_limited", return_value=(False, None)):
            # Yield the app for tests
            with app.app_context():
                yield app


@pytest.fixture(scope="function")
def client(app, mock_redis):
    """Create a test client for the Flask application."""
    with app.test_client() as client:
        yield client


@pytest.fixture(scope="function")
def mock_redis():
    """Create a mock redis client using fakeredis."""
    # Create a fake Redis server
    fake_server = fakeredis.FakeServer()
    fake_redis = fakeredis.FakeRedis(server=fake_server)

    # Mock all redis connections with fake redis
    with patch("redis.Redis.from_url", return_value=fake_redis):
        with patch("redis.from_url", return_value=fake_redis):
            yield fake_redis


@pytest.fixture(scope="function")
def mock_redis_client(mock_redis):
    """Create a mock RedisClient that uses fakeredis."""
    # Create a real RedisClient instance
    redis_client = RedisClient()

    # Apply the patch
    with patch.object(redis_client, "_get_connection", return_value=mock_redis):
        yield redis_client


@pytest.fixture(scope="function")
def auth_header():
    """Create a mock authorization header."""
    return {"Authorization": "Bearer test-token"}


@pytest.fixture(scope="function")
def logged_in_client(client, monkeypatch):
    """Create a test client with an active session."""
    with client.session_transaction() as session:
        session["logged_in"] = True
        session["user_id"] = "test-user-id"
        session["username"] = "test-user"
        session["is_admin"] = False
        session["token"] = "test-token"

    return client


@pytest.fixture(scope="function")
def admin_client(client, monkeypatch):
    """Create a test client with an active admin session."""
    with client.session_transaction() as session:
        session["logged_in"] = True
        session["user_id"] = "admin-user-id"
        session["username"] = "admin-user"
        session["is_admin"] = True
        session["token"] = "admin-token"

    return client
