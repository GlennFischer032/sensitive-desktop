"""Unit tests for the security module."""

from datetime import timedelta
import json
import os

from desktop_manager.config.security import (
    PasswordRequirements,
    SecuritySettings,
    get_password_requirements,
    get_security_settings,
    validate_password_requirements,
)


def test_security_settings_defaults():
    """Test that SecuritySettings has the expected default values."""
    settings = SecuritySettings()

    # Password settings
    assert settings.MIN_PASSWORD_LENGTH == 8
    assert (
        settings.PASSWORD_REGEX
        == r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    )
    assert settings.PASSWORD_HASH_ROUNDS == 12

    # Token settings
    assert settings.JWT_ALGORITHM == "HS512"
    assert settings.ACCESS_TOKEN_EXPIRE_MINUTES == 15
    assert settings.REFRESH_TOKEN_EXPIRE_DAYS == 7

    # Session settings
    assert settings.SESSION_COOKIE_NAME == "__Secure-session"
    assert settings.SESSION_COOKIE_SECURE is True
    assert settings.SESSION_COOKIE_HTTPONLY is True
    assert settings.SESSION_COOKIE_SAMESITE == "Strict"
    assert timedelta(minutes=30) == settings.SESSION_LIFETIME

    # CORS settings
    assert isinstance(settings.CORS_ALLOWED_ORIGINS, set)
    assert "http://localhost:5000" in settings.CORS_ALLOWED_ORIGINS
    assert "http://localhost:5001" in settings.CORS_ALLOWED_ORIGINS
    assert "GET" in settings.CORS_ALLOWED_METHODS
    assert "POST" in settings.CORS_ALLOWED_METHODS
    assert "Authorization" in settings.CORS_ALLOWED_HEADERS
    assert "Content-Type" in settings.CORS_ALLOWED_HEADERS
    assert settings.CORS_SUPPORTS_CREDENTIALS is True
    assert settings.CORS_MAX_AGE == 3600

    # Rate limiting settings
    assert settings.RATE_LIMIT_DEFAULT_REQUESTS_PER_SECOND == 5
    assert settings.RATE_LIMIT_DEFAULT_REQUESTS_PER_MINUTE == 30
    assert settings.RATE_LIMIT_DEFAULT_REQUESTS_PER_HOUR == 500

    # Content security settings
    assert 5 * 1024 * 1024 == settings.MAX_CONTENT_LENGTH
    assert "application/json" in settings.ALLOWED_CONTENT_TYPES

    # Security headers
    assert "X-Content-Type-Options" in settings.SECURITY_HEADERS
    assert settings.SECURITY_HEADERS["X-Content-Type-Options"] == "nosniff"
    assert "Content-Security-Policy" in settings.SECURITY_HEADERS
    assert "default-src 'self'" in settings.SECURITY_HEADERS["Content-Security-Policy"]

    # CSRF settings
    assert settings.CSRF_ENABLED is True
    assert settings.CSRF_TOKEN_EXPIRE_MINUTES == 60
    assert settings.CSRF_COOKIE_NAME == "__Secure-csrf-token"
    assert settings.CSRF_COOKIE_SECURE is True
    assert settings.CSRF_COOKIE_HTTPONLY is True
    assert settings.CSRF_COOKIE_SAMESITE == "Strict"


def test_security_settings_from_env():
    """Test that SecuritySettings loads values from environment variables."""
    # Save current environment variables
    old_env = dict(os.environ)

    try:
        # Set test environment variables with SECURITY_ prefix (due to env_prefix in Config)
        test_values = {
            "SECURITY_MIN_PASSWORD_LENGTH": "10",
            "SECURITY_PASSWORD_HASH_ROUNDS": "14",
            "SECURITY_JWT_ALGORITHM": "HS256",
            "SECURITY_ACCESS_TOKEN_EXPIRE_MINUTES": "30",
            "SECURITY_REFRESH_TOKEN_EXPIRE_DAYS": "14",
            "SECURITY_SESSION_COOKIE_NAME": "test_session",
            "SECURITY_SESSION_COOKIE_SECURE": "False",
            # Use JSON format for sets and lists
            "SECURITY_CORS_ALLOWED_ORIGINS": json.dumps(
                ["https://test.com", "https://example.com"]
            ),
            "SECURITY_RATE_LIMIT_DEFAULT_REQUESTS_PER_SECOND": "10",
            "SECURITY_CSRF_ENABLED": "False",
            "SECURITY_CSRF_TOKEN_EXPIRE_MINUTES": "120",
        }

        for k, v in test_values.items():
            os.environ[k] = v

        # Create new settings instance to pick up environment variables
        settings = SecuritySettings()

        # Check that values were loaded from environment
        assert settings.MIN_PASSWORD_LENGTH == 10
        assert settings.PASSWORD_HASH_ROUNDS == 14
        assert settings.JWT_ALGORITHM == "HS256"
        assert settings.ACCESS_TOKEN_EXPIRE_MINUTES == 30
        assert settings.REFRESH_TOKEN_EXPIRE_DAYS == 14
        assert settings.SESSION_COOKIE_NAME == "test_session"
        assert settings.SESSION_COOKIE_SECURE is False
        assert "https://test.com" in settings.CORS_ALLOWED_ORIGINS
        assert "https://example.com" in settings.CORS_ALLOWED_ORIGINS
        assert settings.RATE_LIMIT_DEFAULT_REQUESTS_PER_SECOND == 10
        assert settings.CSRF_ENABLED is False
        assert settings.CSRF_TOKEN_EXPIRE_MINUTES == 120

    finally:
        # Restore environment variables
        os.environ.clear()
        os.environ.update(old_env)


def test_password_requirements_model():
    """Test PasswordRequirements model validation and defaults."""
    # Test default values
    requirements = PasswordRequirements(min_length=8)
    assert requirements.min_length == 8
    assert requirements.require_uppercase is True
    assert requirements.require_lowercase is True
    assert requirements.require_numbers is True
    assert requirements.require_special_chars is True
    assert requirements.special_chars == "@$!%*?&#"

    # Test custom values
    custom_requirements = PasswordRequirements(
        min_length=12,
        require_uppercase=False,
        require_lowercase=True,
        require_numbers=True,
        require_special_chars=False,
        special_chars="!@#",
    )
    assert custom_requirements.min_length == 12
    assert custom_requirements.require_uppercase is False
    assert custom_requirements.require_lowercase is True
    assert custom_requirements.require_numbers is True
    assert custom_requirements.require_special_chars is False
    assert custom_requirements.special_chars == "!@#"


def test_get_security_settings():
    """Test the get_security_settings function."""
    settings = get_security_settings()
    assert isinstance(settings, SecuritySettings)
    # Verify at least one property to confirm it's properly initialized
    assert settings.MIN_PASSWORD_LENGTH == 8


def test_get_password_requirements():
    """Test the get_password_requirements function."""
    requirements = get_password_requirements()
    assert isinstance(requirements, PasswordRequirements)
    assert requirements.min_length == get_security_settings().MIN_PASSWORD_LENGTH
    assert requirements.require_uppercase is True
    assert requirements.require_lowercase is True
    assert requirements.require_numbers is True
    assert requirements.require_special_chars is True
    assert requirements.special_chars == "@$!%*?&#"


def test_validate_password_requirements():
    """Test the validate_password_requirements function."""
    # Valid password with all requirements
    assert validate_password_requirements("Passw0rd!") is True

    # Invalid passwords
    # Too short
    assert validate_password_requirements("Pw0rd!") is False

    # No uppercase
    assert validate_password_requirements("passw0rd!") is False

    # No lowercase
    assert validate_password_requirements("PASSW0RD!") is False

    # No numbers
    assert validate_password_requirements("Password!") is False

    # No special characters
    assert validate_password_requirements("Passw0rd") is False


def test_validate_password_requirements_custom():
    """Test validate_password_requirements with custom requirements."""
    # Save original function
    original_get_requirements = get_password_requirements

    try:
        # Override the get_password_requirements function for this test
        def custom_get_requirements():
            return PasswordRequirements(
                min_length=8,  # Min length must be at least 8 due to model constraint
                require_uppercase=False,
                require_lowercase=True,
                require_numbers=True,
                require_special_chars=False,
                special_chars="@#",
            )

        # Replace the function in the module being tested
        import desktop_manager.config.security

        desktop_manager.config.security.get_password_requirements = custom_get_requirements

        # Test with the custom requirements
        # Valid with the new requirements (no uppercase, no special chars required)
        assert desktop_manager.config.security.validate_password_requirements("passw0rd") is True

        # Invalid - too short (less than 8 chars)
        assert desktop_manager.config.security.validate_password_requirements("pssw0rd") is False

        # Invalid - no lowercase
        assert desktop_manager.config.security.validate_password_requirements("PASSW0RD") is False

        # Invalid - no numbers
        assert desktop_manager.config.security.validate_password_requirements("password") is False

    finally:
        # Restore the original function
        desktop_manager.config.security.get_password_requirements = original_get_requirements
