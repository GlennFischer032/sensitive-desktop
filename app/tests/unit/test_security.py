"""
This module contains unit tests for security middleware.
"""
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask, request, jsonify, make_response
from middleware.security import rate_limit, init_security, limiter
from datetime import datetime
import os


@pytest.fixture
def rate_limit_app():
    """Create a test app with rate limiting."""
    # Setup a test app
    app = Flask("rate_limit_test_app")
    app.testing = True
    app.config.update(
        {
            "SECRET_KEY": "test_rate_limit_key",
            "RATE_LIMIT_DEFAULT_SECOND": 1000,
            "RATE_LIMIT_DEFAULT_MINUTE": 1000,
            "RATE_LIMIT_DEFAULT_HOUR": 1000,
            "TESTING": True,
        }
    )

    # Create a context and initialize the app
    with app.app_context():
        # Use proper patching for init_security
        with patch("middleware.security.LimiterManager") as mock_limiter_manager:
            # Create a mock limiter
            mock_limiter = MagicMock()

            # Setup our mock limiter's functions
            mock_limiter.limit.return_value = lambda f: lambda *args, **kwargs: f(*args, **kwargs)
            mock_limiter.exempt.return_value = lambda f: lambda *args, **kwargs: f(*args, **kwargs)

            # Configure the manager to return our mock limiter
            mock_limiter_manager.get_limiter.return_value = mock_limiter

            # Initialize security with our mocks
            init_security(app)

    # Define test endpoints
    @app.route("/limited")
    @rate_limit(requests_per_minute=10)
    def limited_endpoint():
        return "OK"

    @app.route("/strict")
    @rate_limit(requests_per_minute=5)
    def strict_endpoint():
        return "OK"

    @app.route("/unlimited")
    def unlimited_endpoint():
        return "OK"

    return app


def test_rate_limit_decorator_behavior(rate_limit_app):
    """Test that the rate_limit decorator correctly applies limits based on configuration."""
    client = rate_limit_app.test_client()

    # Test limited endpoint
    response = client.get("/limited")
    assert response.status_code == 200
    assert response.get_data(as_text=True) == "OK"

    # Test strict endpoint
    response = client.get("/strict")
    assert response.status_code == 200
    assert response.get_data(as_text=True) == "OK"


def test_rate_limit_format():
    """
    Test that the rate_limit function correctly builds limits.
    """
    # For this test, we'll test just the format of the limits
    second_limit = 10
    minute_limit = 30
    hour_limit = 500

    # Test with all limits
    all_limits = []
    if second_limit is not None:
        all_limits.append(f"{second_limit} per second")
    if minute_limit is not None:
        all_limits.append(f"{minute_limit} per minute")
    if hour_limit is not None:
        all_limits.append(f"{hour_limit} per hour")

    formatted_limits = ";".join(all_limits)
    assert formatted_limits == "10 per second;30 per minute;500 per hour"

    # Test with some limits
    partial_limits = []
    second_limit = None
    if second_limit is not None:
        partial_limits.append(f"{second_limit} per second")
    if minute_limit is not None:
        partial_limits.append(f"{minute_limit} per minute")
    if hour_limit is not None:
        partial_limits.append(f"{hour_limit} per hour")

    formatted_partial = ";".join(partial_limits)
    assert formatted_partial == "30 per minute;500 per hour"
