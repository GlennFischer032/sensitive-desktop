import os
import sys
import pytest
from flask import Flask, session
import fakeredis
import datetime
import jwt
from unittest.mock import patch, MagicMock

# Add the src directory to the path so we can import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

# Import the create_app function
from __init__ import create_app


class TestConfig:
    """Test configuration"""

    SECRET_KEY = "test_secret_key"
    DEBUG = True
    TESTING = True
    API_URL = "http://localhost:5000"

    # Use null session for testing
    SESSION_TYPE = "null"

    # Security configuration
    JWT_ALGORITHM = "HS256"

    # CORS configuration
    CORS_ALLOWED_ORIGINS = ["http://localhost:5000"]
    CORS_SUPPORTS_CREDENTIALS = True

    # Rate limiting configuration
    RATE_LIMIT_DEFAULT_SECOND = 1000
    RATE_LIMIT_DEFAULT_MINUTE = 1000
    RATE_LIMIT_DEFAULT_HOUR = 1000

    # Content Security Policy
    CSP_POLICY = {
        "default-src": ["'self'"],
        "script-src": ["'self'"],
        "style-src": ["'self'"],
        "img-src": ["'self'"],
        "font-src": ["'self'"],
        "connect-src": ["'self'"],
        "frame-src": ["'self'"],
    }


@pytest.fixture(scope="module")
def app():
    """Create and configure a Flask app for testing."""
    # Create mocks
    redis_client_mock = MagicMock()
    redis_client_mock._get_connection.return_value = fakeredis.FakeStrictRedis()
    redis_client_mock.zremrangebyscore.return_value = 0
    redis_client_mock.zadd.return_value = 0
    redis_client_mock.zcard.return_value = 0
    redis_client_mock.zrange.return_value = []
    redis_client_mock.pipeline.return_value = MagicMock()

    # Mock the rate limiter for testing
    with patch("middleware.security.LimiterManager") as mock_limiter_manager:
        # Create a mock limiter
        mock_limiter = MagicMock()

        # Set up the mock limiter's methods to pass through the decorated functions
        mock_limiter.limit.return_value = lambda f: f
        mock_limiter.exempt.return_value = lambda f: f

        # Configure the manager to return our mock limiter
        mock_limiter_manager.get_limiter.return_value = mock_limiter

        # Create app with test config
        app = create_app(TestConfig)
        app.config.update({"TESTING": True})

        # Create application context
        with app.app_context():
            yield app


@pytest.fixture(scope="function")
def client(app):
    """A test client for the app."""
    return JSONTestClient(app.test_client())


@pytest.fixture(scope="function")
def runner(app):
    """A test CLI runner for the app."""
    return app.test_cli_runner()


@pytest.fixture
def auth_token(app):
    """Generate a valid JWT token for testing."""
    payload = {
        "sub": "test_user",
        "name": "Test User",
        "email": "test@example.com",
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        "roles": ["user"],
    }
    token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm=app.config["JWT_ALGORITHM"])
    return token


@pytest.fixture
def admin_token(app):
    """Generate a valid JWT token with admin role for testing."""
    payload = {
        "sub": "admin_user",
        "name": "Admin User",
        "email": "admin@example.com",
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        "roles": ["admin"],
    }
    token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm=app.config["JWT_ALGORITHM"])
    return token


@pytest.fixture(scope="function")
def logged_in_client(client, auth_token):
    """A test client with an active user session."""
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["token"] = auth_token
        sess["user"] = {"id": "test_user", "name": "Test User", "email": "test@example.com"}
    return client


@pytest.fixture(scope="function")
def admin_client(client, admin_token):
    """A test client with an active admin session."""
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["token"] = admin_token
        sess["user"] = {"id": "admin_user", "name": "Admin User", "email": "admin@example.com"}
        sess["is_admin"] = True
    return client


class JSONTestClient:
    """A test client wrapper that adds Content-Type header to all requests."""

    def __init__(self, app_test_client):
        self.app_test_client = app_test_client
        # Pass through application attribute
        self.application = app_test_client.application

    def get(self, *args, **kwargs):
        return self.app_test_client.get(*args, **kwargs)

    def post(self, *args, **kwargs):
        if "headers" not in kwargs:
            kwargs["headers"] = {}
        kwargs["headers"]["Content-Type"] = "application/json"
        return self.app_test_client.post(*args, **kwargs)

    def put(self, *args, **kwargs):
        if "headers" not in kwargs:
            kwargs["headers"] = {}
        kwargs["headers"]["Content-Type"] = "application/json"
        return self.app_test_client.put(*args, **kwargs)

    def delete(self, *args, **kwargs):
        if "headers" not in kwargs:
            kwargs["headers"] = {}
        kwargs["headers"]["Content-Type"] = "application/json"
        return self.app_test_client.delete(*args, **kwargs)

    def session_transaction(self, *args, **kwargs):
        return self.app_test_client.session_transaction(*args, **kwargs)

    # Forward any other attributes to the wrapped test client
    def __getattr__(self, name):
        return getattr(self.app_test_client, name)
