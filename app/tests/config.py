"""Test configuration for the frontend application."""

from datetime import timedelta

from config.config import Config


class TestConfig(Config):
    """Test configuration class."""

    TESTING = True
    SECRET_KEY = "test-secret-key"
    WTF_CSRF_ENABLED = False
    SESSION_TYPE = "null"  # Use null session type for testing
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)  # Set session lifetime
    SESSION_COOKIE_SECURE = False  # Allow non-HTTPS in testing
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    API_URL = "http://test-api:5000"  # Will be mocked in tests
    GUACAMOLE_URL = "http://test-guacamole:8080"  # Will be mocked in tests
    SKIP_AUTH_FOR_TESTING = True  # Skip authentication checks in tests

    # Security settings for testing
    CORS_ALLOWED_ORIGINS = ["http://test-api:5000"]
    RATE_LIMIT_DEFAULT_SECOND = 1000000  # Effectively disable rate limiting for tests
    RATE_LIMIT_DEFAULT_MINUTE = 1000000
    RATE_LIMIT_DEFAULT_HOUR = 1000000

    # OIDC settings for testing
    OIDC_CLIENT_ID = "test-client-id"
    OIDC_CLIENT_SECRET = "test-client-secret"
    OIDC_PROVIDER_URL = "http://test-oidc-provider"
    OIDC_REDIRECT_URI = "http://localhost:5001/auth/oidc/callback"

    # Skip authentication for testing
    SKIP_AUTH_FOR_TESTING = True
