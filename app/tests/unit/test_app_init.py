"""
This module contains unit tests for application initialization.
"""
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask


def test_app_initialization(app):
    """
    GIVEN a Flask application configured for testing
    WHEN the application is initialized
    THEN check that it's configured correctly
    """
    assert isinstance(app, Flask)
    assert app.testing

    # Check core blueprints are registered by checking some view functions
    # Since flask uses endpoint names like "auth.login", check for these
    view_functions = list(app.view_functions.keys())

    # Check that some auth endpoints exist
    assert any(endpoint.startswith("auth.") for endpoint in view_functions)

    # Check that some connections endpoints exist
    assert any(endpoint.startswith("connections.") for endpoint in view_functions)

    # Check core routes - health_check is now handled at WSGI level before Flask
    assert "index" in view_functions
    assert "test_api_connection" in view_functions


def test_app_error_handlers(app):
    """
    GIVEN a Flask application configured for testing
    WHEN the application is initialized
    THEN check that error handlers are registered
    """
    # Check error handlers are registered
    assert 404 in app.error_handler_spec[None]
    assert 500 in app.error_handler_spec[None]
    assert 429 in app.error_handler_spec[None]
    assert 403 in app.error_handler_spec[None]


@patch("clients.factory.client_factory.get_redis_client")
def test_session_initialization(mock_get_redis_client, app):
    """
    GIVEN a Flask application
    WHEN the session is initialized
    THEN check that the session is configured correctly based on app config
    """
    from __init__ import init_session

    # Test with regular (non-null) session type
    app.config["SESSION_TYPE"] = "redis"

    # Create mock Redis client
    mock_redis = MagicMock()
    mock_get_redis_client.return_value = mock_redis
    mock_redis.get_client_for_session.return_value = "redis-client-instance"

    # Initialize session
    init_session(app)

    # Check Redis session is configured
    assert app.config["SESSION_REDIS"] == "redis-client-instance"
    assert app.config["SESSION_REFRESH_EACH_REQUEST"] is True

    # Test with null session type (for testing)
    app.config["SESSION_TYPE"] = "null"
    init_session(app)


@patch("flask_session.redis.redis.Redis.set")
def test_security_headers_middleware(mock_redis_set, app):
    """
    GIVEN a Flask application
    WHEN a request is made
    THEN check that security headers are added to the response
    """
    # Configure for testing without Redis
    app.config["SESSION_TYPE"] = "null"

    client = app.test_client()

    # First verify the health endpoint works correctly
    # It should have security headers but no HTTPS enforcement
    health_response = client.get("/health")
    assert health_response.status_code == 200
    assert health_response.json == {"status": "healthy"}

    # Health check should have security headers, but it should not force HTTPS
    assert health_response.headers.get("X-Content-Type-Options") == "nosniff"
    # Ensure no Location header forcing HTTPS
    assert "Location" not in health_response.headers

    # For other routes security headers are also applied
    response = client.get("/nonexistent-page")

    # We expect security headers on regular routes, regardless of status code
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    # Check for Content Security Policy header
    assert "default-src 'self'" in response.headers.get("Content-Security-Policy", "")
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    # In test environment, HSTS is not enabled due to force_https=False
