from datetime import timedelta
import os
from typing import Dict, Set

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class SecuritySettings(BaseSettings):
    """Security configuration settings."""

    # Password settings
    MIN_PASSWORD_LENGTH: int = 8
    # This is a regex pattern for validation, not an actual password
    PASSWORD_REGEX: str = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    PASSWORD_HASH_ROUNDS: int = 12

    # Token settings
    JWT_SECRET_KEY: str = os.environ.get("SECRET_KEY", "")
    JWT_ALGORITHM: str = "HS512"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Session settings
    SESSION_COOKIE_NAME: str = "__Secure-session"
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Strict"
    SESSION_LIFETIME: timedelta = timedelta(minutes=30)

    # CORS settings
    CORS_ALLOWED_ORIGINS: Set[str] = set(
        os.environ.get("CORS_ALLOWED_ORIGINS", "http://localhost:5000,http://localhost:5001").split(
            ","
        )
    )
    CORS_ALLOWED_METHODS: Set[str] = {"GET", "POST", "PUT", "DELETE", "OPTIONS"}
    CORS_ALLOWED_HEADERS: Set[str] = {
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "Accept",
        "Origin",
        "X-CSRF-Token",
    }
    CORS_EXPOSE_HEADERS: Set[str] = {"Content-Length", "Content-Range", "X-Total-Count"}
    CORS_SUPPORTS_CREDENTIALS: bool = True
    CORS_MAX_AGE: int = 3600

    # Rate limiting settings
    RATE_LIMIT_DEFAULT_REQUESTS_PER_SECOND: int = 5
    RATE_LIMIT_DEFAULT_REQUESTS_PER_MINUTE: int = 30
    RATE_LIMIT_DEFAULT_REQUESTS_PER_HOUR: int = 500

    # Content security settings
    MAX_CONTENT_LENGTH: int = 5 * 1024 * 1024
    ALLOWED_CONTENT_TYPES: Set[str] = {
        "application/json",
        "multipart/form-data",
        "application/x-www-form-urlencoded",
    }

    # Security headers
    SECURITY_HEADERS: Dict[str, str] = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            # Allow inline scripts and eval for dynamic UI
            "style-src 'self' 'unsafe-inline'; "  # Allow inline styles for UI components
            "img-src 'self' data:; "
            "font-src 'self' data:; "  # Allow data URIs for fonts
            "connect-src 'self' http://localhost:* http://127.0.0.1:*; "
            # Allow local development connections
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "object-src 'none'; "  # Disable object/plugin content
            "upgrade-insecure-requests"
        ),
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": (
            "accelerometer=(), "
            "camera=(), "
            "geolocation=(), "
            "gyroscope=(), "
            "magnetometer=(), "
            "microphone=(), "
            "payment=(), "
            "usb=(), "
            "interest-cohort=(), "
            "ambient-light-sensor=(), "
            "autoplay=(), "
            "battery=(), "
            "display-capture=(), "
            "document-domain=(), "
            "encrypted-media=(), "
            "execution-while-not-rendered=(), "
            "execution-while-out-of-viewport=(), "
            "fullscreen=(), "
            "publickey-credentials-get=(), "
            "screen-wake-lock=(), "
            "web-share=(), "
            "xr-spatial-tracking=()"
        ),
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Cache-Control": "no-store, max-age=0",
        "Clear-Site-Data": '"cache", "cookies", "storage"',
    }

    # Added CSRF protection settings
    CSRF_ENABLED: bool = True
    CSRF_TOKEN_EXPIRE_MINUTES: int = 60
    CSRF_COOKIE_NAME: str = "__Secure-csrf-token"
    CSRF_COOKIE_SECURE: bool = True
    CSRF_COOKIE_HTTPONLY: bool = True
    CSRF_COOKIE_SAMESITE: str = "Strict"

    class Config:
        env_prefix = "SECURITY_"
        case_sensitive = True


class PasswordRequirements(BaseModel):
    """Password requirements schema."""

    min_length: int = Field(..., ge=8)
    require_uppercase: bool = Field(True)
    require_lowercase: bool = Field(True)
    require_numbers: bool = Field(True)
    require_special_chars: bool = Field(True)
    special_chars: str = Field("@$!%*?&#")


def get_security_settings() -> SecuritySettings:
    """Get security settings instance."""
    return SecuritySettings()


def get_password_requirements() -> PasswordRequirements:
    """Get password requirements instance."""
    return PasswordRequirements(
        min_length=get_security_settings().MIN_PASSWORD_LENGTH,
        require_uppercase=True,
        require_lowercase=True,
        require_numbers=True,
        require_special_chars=True,
        special_chars="@$!%*?&#",
    )


def validate_password_requirements(password: str) -> bool:
    """Validate password against requirements.

    Args:
        password: Password to validate

    Returns:
        bool: True if password meets requirements, False otherwise
    """
    requirements = get_password_requirements()

    if len(password) < requirements.min_length:
        return False

    if requirements.require_uppercase and not any(c.isupper() for c in password):
        return False

    if requirements.require_lowercase and not any(c.islower() for c in password):
        return False

    if requirements.require_numbers and not any(c.isdigit() for c in password):
        return False

    return not (
        requirements.require_special_chars
        and not any(c in requirements.special_chars for c in password)
    )
