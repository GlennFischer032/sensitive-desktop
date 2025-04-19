"""
This module contains unit tests for the application configuration.
"""


def test_app_config_values(app):
    """
    GIVEN a Flask application configured for testing
    WHEN the application is created with testing configurations
    THEN check that the app.config reflects the test configuration values
    """
    assert app.config["TESTING"] is True
    assert app.config["DEBUG"] is True
    assert app.config["SECRET_KEY"] == "test_secret_key"
    assert app.config["SESSION_TYPE"] == "null"
    assert app.config["API_URL"] == "http://localhost:5000"
    assert app.config["JWT_ALGORITHM"] == "HS256"

    # Check rate limiting config
    assert app.config["RATE_LIMIT_DEFAULT_SECOND"] == 1000
    assert app.config["RATE_LIMIT_DEFAULT_MINUTE"] == 1000
    assert app.config["RATE_LIMIT_DEFAULT_HOUR"] == 1000

    # Check CORS configuration
    assert "http://localhost:5000" in app.config["CORS_ALLOWED_ORIGINS"]
    assert app.config["CORS_SUPPORTS_CREDENTIALS"] is True

    # Check CSP configuration
    assert "default-src" in app.config["CSP_POLICY"]
    assert "'self'" in app.config["CSP_POLICY"]["default-src"]
