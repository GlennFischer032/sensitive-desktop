from cachelib import NullCache
from flask import Config


class TestConfig(Config):
    """Test configuration class"""

    # Enable testing mode
    TESTING = True

    # Disable debug mode
    DEBUG = False

    # Use a test secret key
    SECRET_KEY = "test-secret-key"

    # Use a test API URL that won't be actually called in tests
    # since we're mocking the actual calls
    API_URL = "http://localhost:5000/api"

    # Use null cache for session storage in tests
    SESSION_TYPE = "null"
    SESSION_PERMANENT = False
    SESSION_CACHELIB = NullCache()

    # Use a dummy Redis URL for testing
    SESSION_REDIS = "redis://localhost:6379/0"

    # Disable secure cookies for testing
    SESSION_COOKIE_SECURE = False

    # Disable CSRF protection for testing API calls
    WTF_CSRF_ENABLED = False

    # Use higher rate limits for tests
    RATE_LIMIT_DEFAULT_SECOND = 1000
    RATE_LIMIT_DEFAULT_MINUTE = 5000
    RATE_LIMIT_DEFAULT_HOUR = 10000
