from typing import Dict, Any, Set
from datetime import timedelta
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

class SecuritySettings(BaseSettings):
    """Security configuration settings."""
    
    # Password settings
    MIN_PASSWORD_LENGTH: int = 8
    PASSWORD_REGEX: str = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    PASSWORD_HASH_ROUNDS: int = 12
    
    # Token settings
    JWT_SECRET_KEY: str = "your-secret-key"  # Should be overridden in production
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Session settings
    SESSION_COOKIE_NAME: str = "session"
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"
    SESSION_LIFETIME: timedelta = timedelta(hours=1)
    
    # CORS settings
    CORS_ALLOWED_ORIGINS: Set[str] = {"http://localhost:5000", "http://localhost:5001"}
    CORS_ALLOWED_METHODS: Set[str] = {"GET", "POST", "PUT", "DELETE", "OPTIONS"}
    CORS_ALLOWED_HEADERS: Set[str] = {
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "Accept"
    }
    CORS_EXPOSE_HEADERS: Set[str] = {"Content-Length", "Content-Range"}
    CORS_SUPPORTS_CREDENTIALS: bool = True
    CORS_MAX_AGE: int = 3600
    
    # Rate limiting settings
    RATE_LIMIT_DEFAULT_REQUESTS_PER_SECOND: int = 10
    RATE_LIMIT_DEFAULT_REQUESTS_PER_MINUTE: int = 100
    RATE_LIMIT_DEFAULT_REQUESTS_PER_HOUR: int = 1000
    
    # Content security settings
    MAX_CONTENT_LENGTH: int = 10 * 1024 * 1024  # 10MB
    ALLOWED_CONTENT_TYPES: Set[str] = {
        "application/json",
        "multipart/form-data",
        "application/x-www-form-urlencoded"
    }
    
    # Security headers
    SECURITY_HEADERS: Dict[str, str] = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'"
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
            "usb=()"
        )
    }
    
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
        special_chars="@$!%*?&#"
    )

def validate_password_requirements(password: str) -> bool:
    """
    Validate password against requirements.
    
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
        
    if (requirements.require_special_chars and 
        not any(c in requirements.special_chars for c in password)):
        return False
        
    return True 