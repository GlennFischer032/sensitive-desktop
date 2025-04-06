import logging
import os


class Config:
    """Application configuration class"""

    # Flask configuration
    SECRET_KEY = os.environ.get("SECRET_KEY", "")

    # Debug options
    DEBUG = os.environ.get("DEBUG", "false").lower() == "true"

    # API endpoints
    API_URL = os.environ.get("API_URL", "http://localhost:5000")
    EXTERNAL_GUACAMOLE_URL = os.environ.get("EXTERNAL_GUACAMOLE_URL", "http://guacamole:8080/guacamole")

    # Logging configuration
    LOG_LEVEL = logging.INFO

    # Session configuration
    SESSION_TYPE = "redis"
    SESSION_REDIS = os.environ.get("REDIS_URL", "redis://redis:6379/0")
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes
    SESSION_COOKIE_SECURE = True if os.environ.get("DEBUG", "false").lower() == "false" else False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_KEY_PREFIX = "desktop_frontend:"
    SESSION_USE_SIGNER = True
    SESSION_COOKIE_NAME = "desktop_frontend_session"

    # Security configuration
    JWT_ALGORITHM = "HS256"

    # CORS configuration
    CORS_ALLOWED_ORIGINS = [
        "http://localhost:5000",
        "http://localhost:5001",
        "http://desktop-api:5000",
        "http://desktop-frontend:80",
    ]
    CORS_SUPPORTS_CREDENTIALS = True
    CORS_EXPOSE_HEADERS = ["Content-Range", "X-Total-Count"]
    CORS_ALLOWED_HEADERS = [
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "Accept",
        "Origin",
    ]
    CORS_ALLOWED_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    CORS_MAX_AGE = 3600

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
