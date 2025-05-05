import os
import sys
import tempfile
import pytest
from flask import Flask
from flask.testing import FlaskClient
from typing import Generator, Any
import logging
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from contextlib import contextmanager
from datetime import datetime, timedelta
import jwt

# Configure coverage to include src directory
os.environ["COVERAGE_FILE"] = ".coverage"
if "PYTHONPATH" in os.environ:
    os.environ["PYTHONPATH"] = f"{os.environ['PYTHONPATH']}:{os.path.abspath('src')}"
else:
    os.environ["PYTHONPATH"] = os.path.abspath("src")

# Add the src directory to the path so we can import the app module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

# Create test engine and session factory
test_engine = create_engine("sqlite:///:memory:")
TestingSessionLocal = sessionmaker(bind=test_engine)


@pytest.fixture(scope="session")
def setup_test_db():
    """Set up a test database with tables."""
    from schemas.base import Base

    # Create all tables in the in-memory database
    Base.metadata.create_all(bind=test_engine)
    yield
    # Clean up (optional for in-memory database)
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="function")
def db_session(setup_test_db):
    """Get a test database session."""
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


# Mock config settings
class MockSettings:
    SECRET_KEY = "test_secret"
    OIDC_PROVIDER_URL = "http://test-provider"
    OIDC_CLIENT_ID = "test-client"
    OIDC_CLIENT_SECRET = "test-secret"
    OIDC_BACKEND_REDIRECT_URI = "http://localhost/callback"
    FRONTEND_URL = "http://localhost"
    OIDC_REDIRECT_URI = "http://localhost/callback"
    CORS_ALLOWED_ORIGINS = "http://localhost"
    database_url = "sqlite:///:memory:"
    ADMIN_OIDC_SUB = "test-admin-sub"
    ADMIN_EMAIL = "admin@example.com"
    ADMIN_USERNAME = "admin"
    ADMIN_PASSWORD = "admin-password"
    ADMIN_FIRST_NAME = "Admin"
    ADMIN_LAST_NAME = "User"
    LOG_LEVEL = "DEBUG"


@pytest.fixture(scope="session", autouse=True)
def mock_settings():
    """Mock settings for the entire test suite."""
    with patch("config.settings.get_settings", return_value=MockSettings()):
        yield


@pytest.fixture(scope="function", autouse=True)
def mock_user_service():
    """Mock the UserService to avoid initializing the admin user."""
    with patch("services.user.UserService") as mock:
        # Create a mock instance with init_admin_user method
        mock_instance = MagicMock()
        mock_instance.init_admin_user.return_value = None
        mock.return_value = mock_instance
        yield mock_instance


# Mock get_engine and get_db_session functions
@pytest.fixture(scope="function", autouse=True)
def mock_db(monkeypatch):
    """Mock database connections."""
    from database.core import session as db_session_module

    # Mock get_engine
    def mock_get_engine():
        return test_engine

    # Mock get_db_session
    @contextmanager
    def mock_get_db_session():
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.rollback()
            session.close()

    # Apply mocks
    monkeypatch.setattr(db_session_module, "get_engine", mock_get_engine)
    monkeypatch.setattr(db_session_module, "get_db_session", mock_get_db_session)
    monkeypatch.setattr(db_session_module, "initialize_db", lambda: None)  # Skip DB initialization


@pytest.fixture(scope="function")
def test_app():
    """
    Create and configure a Flask app for testing.

    Returns:
        Flask application instance configured for testing
    """
    # We need to patch the UserService for admin user creation
    with patch("main.UserService") as mock_service:
        # Set up the mock to not do anything when init_admin_user is called
        mock_instance = MagicMock()
        mock_instance.init_admin_user.return_value = None
        mock_service.return_value = mock_instance

        # Import create_app after mocking
        from main import create_app

        # Create the Flask app with test config
        app = create_app()
        app.config.update(
            {
                "TESTING": True,
                "SECRET_KEY": "test_secret_key",
                "SERVER_NAME": "localhost",
                "WTF_CSRF_ENABLED": False,
            }
        )

        with app.app_context():
            yield app


@pytest.fixture(scope="function")
def test_client(test_app: Flask) -> FlaskClient:
    """
    Create a test client for the Flask app.

    Args:
        test_app: Flask application instance

    Returns:
        Flask test client
    """
    return test_app.test_client()


# Create a fake user class for testing
class FakeUser:
    def __init__(self):
        self.username = "admin"
        self.is_admin = True
        self.email = "admin@example.com"


@pytest.fixture
def mock_token():
    """Mock token for authorization."""
    return "fake-test-token"


@pytest.fixture
def mock_user_repository():
    """Mock the UserRepository."""
    with patch("database.repositories.user.UserRepository") as mock:
        mock_instance = MagicMock()
        # Mock get_by_sub to return a user
        mock_user = MagicMock()
        mock_user.username = "admin"
        mock_user.is_admin = True
        mock_user.email = "admin@example.com"
        mock_instance.get_by_sub.return_value = mock_user
        mock.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_token_repository():
    """Mock the TokenRepository."""
    with patch("database.repositories.token.TokenRepository") as mock:
        mock_instance = MagicMock()
        # Mock get_by_token_id
        mock_token = MagicMock()
        mock_token.token_id = "test-token-id"
        mock_token.revoked = False
        mock_token.expires_at = datetime.utcnow() + timedelta(days=30)
        mock_token.created_by = "admin"
        mock_instance.get_by_token_id.return_value = mock_token
        mock.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_auth_decorators():
    """Mock all auth decorators and DB session."""

    # Create simple pass-through decorators
    def dummy_decorator(f):
        return f

    # Apply common mocks
    with patch("core.auth.token_required", dummy_decorator), patch("core.auth.admin_required", dummy_decorator), patch(
        "database.core.session.with_db_session", dummy_decorator
    ):
        yield
