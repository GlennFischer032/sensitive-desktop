import os


class Config:
    """Application configuration class"""

    # Flask configuration
    SECRET_KEY = os.environ.get("SECRET_KEY", "")

    # Debug options

    DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"
    # API endpoints

    API_URL = os.environ.get("API_URL", "http://localhost:5000")

    # Logging configuration
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

    # Session configuration
    SESSION_TYPE = "redis"
    SESSION_REDIS = os.environ.get("REDIS_URL", "redis://redis:6379/0")
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes
    SESSION_COOKIE_SECURE = os.environ.get("FLASK_DEBUG", "0") != "1"  # Secure cookies except in debug mode
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_KEY_PREFIX = "desktop_frontend:"
    SESSION_USE_SIGNER = os.environ.get("FLASK_DEBUG", "0") != "1"
    SESSION_COOKIE_NAME = "desktop_frontend_session"

    # Security configuration only for debug mode
    JWT_ALGORITHM = "HS256"

    # Rate limiting configuration
    RATE_LIMIT_DEFAULT_SECOND = 10  # 10 requests per second
    RATE_LIMIT_DEFAULT_MINUTE = 30  # 30 requests per minute
    RATE_LIMIT_DEFAULT_HOUR = 1000  # 1000 requests per hour

    # Content Security Policy
    CSP_POLICY = {
        "default-src": ["'self'"],
        "script-src": ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        "style-src": ["'self'", "'unsafe-inline'"],
        "img-src": ["'self'", "data:", "https://login.e-infra.cz"],
        "font-src": ["'self'"],
        "connect-src": ["'self'", API_URL, "https://login.e-infra.cz"],
        "frame-src": ["'self'", "https://login.e-infra.cz"],
    }
