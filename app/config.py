import os
from datetime import timedelta


class Config:
    """Base configuration for the application."""

    # Basic configuration
    SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(24).hex())

    # Debug settings - controlled by the DEBUG_MODE environment variable
    DEBUG = os.environ.get("DEBUG_MODE", "false").lower() in ("true", "1", "yes")
    DEBUG_LOGIN_ENABLED = DEBUG  # Use the same setting for debug login

    SESSION_TYPE = "filesystem"
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
