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


def test_csp_nonce_context_processor(app):
    """
    GIVEN a Flask application
    WHEN the CSP nonce context processor is used
    THEN check that it provides the expected nonce
    """
    # Get the utility_processor function
    import inspect
    from __init__ import create_app

    # Extract the utility_processor function by inspecting the app creation
    source = inspect.getsource(create_app)
    assert "utility_processor" in source
    assert "csp_nonce" in source

    # Test the context processor inside a request context
    with app.test_request_context():
        from flask import request, render_template_string

        # Manually set a nonce
        request.csp_nonce = "test-nonce-value"

        # Use a template that calls the context processor
        rendered = render_template_string("{{ csp_nonce() }}")
        assert rendered == "test-nonce-value"


def test_datetime_template_filter(app):
    """
    GIVEN a Flask application
    WHEN the datetime template filter is used
    THEN check that it formats datetime objects and strings correctly
    """
    # Check if the filter is registered
    assert "datetime" in app.jinja_env.filters

    # Get the filter function
    filter_func = app.jinja_env.filters["datetime"]

    # Import datetime
    import datetime as dt

    # Test with different inputs
    test_date = dt.datetime(2023, 1, 15, 12, 30, 45)

    # Test with datetime object
    assert filter_func(test_date) == "2023-01-15 12:30:45"

    # Test with ISO string
    assert filter_func("2023-01-15T12:30:45") == "2023-01-15 12:30:45"

    # Test with custom format
    assert filter_func(test_date, "%d/%m/%Y") == "15/01/2023"

    # Test with None
    assert filter_func(None) == ""

    # Test with invalid string
    assert filter_func("not-a-date") == "not-a-date"


def test_rate_limit_check_middleware(app):
    """
    GIVEN a Flask application
    WHEN the rate limit middleware is used
    THEN check that it skips specific routes
    """
    client = app.test_client()

    # Health check should bypass the rate limiter
    response = client.get("/health")
    assert response.status_code == 200

    # Static files should bypass the rate limiter
    # Since we can't mock the Flask-Limiter directly in this test,
    # we just verify the endpoint exists and responds
    response = client.get("/static/nonexistent")
    assert response.status_code == 404  # File doesn't exist but route works


def test_error_handlers_response(app):
    """
    GIVEN a Flask application configured for testing
    WHEN errors occur during a request
    THEN check that the error handlers are registered
    """
    client = app.test_client()

    # Test 404 error handler
    response = client.get("/not-found-page")
    assert response.status_code == 404
    # Check that response contains expected HTML from template
    assert b"<!DOCTYPE html>" in response.data
    assert b"Page Not Found" in response.data

    # Verify error handlers are registered
    assert 404 in app.error_handler_spec[None]
    assert 403 in app.error_handler_spec[None]
    assert 429 in app.error_handler_spec[None]
    assert 500 in app.error_handler_spec[None]


def test_content_type_validation():
    """
    GIVEN a Flask application configured for testing
    WHEN a request with an invalid content type is made
    THEN check that the validation middleware returns a 400 error
    """
    # Import create_app to create a fresh application instance
    from __init__ import create_app
    from config.config import Config

    class TestConfig(Config):
        TESTING = True
        SESSION_TYPE = "null"

    # Create a fresh app instance so we can add routes
    app = create_app(TestConfig)

    # Create a test route that will execute the validation middleware
    @app.route("/test-validation", methods=["POST"])
    def test_validation():
        return {"success": True}

    # Create a test client
    client = app.test_client()

    # Test JSON content type validation for POST request
    response = client.post("/test-validation", headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 400
    assert b"Content-Type must be application/json" in response.data


def test_request_size_validation():
    """
    GIVEN a Flask application configured for testing
    WHEN a request that exceeds the size limit is made
    THEN check that the validation middleware returns a 413 error
    """
    # Import create_app to create a fresh application instance
    from __init__ import create_app
    from config.config import Config

    class TestConfig(Config):
        TESTING = True
        SESSION_TYPE = "null"
        MAX_CONTENT_LENGTH = 10  # Very small limit for testing

    # Create a fresh app instance so we can add routes
    app = create_app(TestConfig)

    # Create a test route
    @app.route("/test-size", methods=["POST"])
    def test_size():
        return {"success": True}

    # Create a test client
    client = app.test_client()

    # Create a request with content larger than the limit
    response = client.post(
        "/test-size", headers={"Content-Type": "application/json"}, data=b'{"data": "' + b"x" * 20 + b'"}'
    )
    assert response.status_code == 413  # Request Entity Too Large
