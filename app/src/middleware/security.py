import logging
from collections.abc import Callable
from datetime import timedelta
from functools import wraps

from clients.factory import client_factory
from flask import Flask, current_app
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

logger = logging.getLogger(__name__)

# Global limiter instance
limiter = None


class LimiterManager:
    """Manager for the Flask-Limiter instance to avoid global variables."""

    _instance = None

    @classmethod
    def get_limiter(cls):
        """Get the limiter instance.

        Returns:
            Limiter: The Flask-Limiter instance
        """
        return cls._instance

    @classmethod
    def initialize(cls, app: Flask):
        """Initialize the limiter with the given app.

        Args:
            app (Flask): The Flask application
        """
        # Initialize rate limiter with Redis storage
        redis_client = client_factory.get_redis_client(app=app)
        redis_client.configure_with_app(app)

        # Configure default limits from app config
        default_limits = [
            f"{app.config.get('RATE_LIMIT_DEFAULT_SECOND', 10)} per second",
            f"{app.config.get('RATE_LIMIT_DEFAULT_MINUTE', 30)} per minute",
            f"{app.config.get('RATE_LIMIT_DEFAULT_HOUR', 1000)} per hour",
        ]

        # Use in-memory storage for testing, Redis otherwise
        if app.config.get("TESTING", False):
            storage_uri = "memory://"
        else:
            # For production, use Redis
            # We can get the Redis URL from the session configuration
            redis_url = app.config.get("SESSION_REDIS", "redis://localhost:6379/0")
            if not isinstance(redis_url, str):
                # If it's already a Redis instance, use localhost with default port
                redis_url = "redis://localhost:6379/0"
            storage_uri = redis_url

        # Create the limiter instance
        cls._instance = Limiter(
            app=app,
            key_func=get_remote_address,
            storage_uri=storage_uri,
            storage_options={"socket_connect_timeout": 30},
            default_limits=default_limits,
            strategy="fixed-window",  # Use fixed time window strategy
            headers_enabled=True,  # Send rate limit headers
            swallow_errors=app.config.get("TESTING", False),  # Swallow errors only in testing
        )


def rate_limit(
    requests_per_second: int | None = None,
    requests_per_minute: int | None = None,
    requests_per_hour: int | None = None,
    override_global: bool = True,
):
    """
    Rate limiting decorator for Flask routes.

    Args:
        requests_per_second: Maximum requests per second
        requests_per_minute: Maximum requests per minute
        requests_per_hour: Maximum requests per hour
        override_global: If True, only these limits are applied.
                        If False, these limits are applied in addition to global limits.
    """

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get the limiter instance
            limiter = LimiterManager.get_limiter()

            # In test environments, just call the function directly
            if limiter is None or current_app.config.get("TESTING", False):
                return f(*args, **kwargs)

            # Prepare the limits
            limits = []
            if requests_per_second is not None:
                limits.append(f"{requests_per_second} per second")
            if requests_per_minute is not None:
                limits.append(f"{requests_per_minute} per minute")
            if requests_per_hour is not None:
                limits.append(f"{requests_per_hour} per hour")

            # Apply rate limiting
            if not limits:
                # No custom limits, either exempt or use defaults
                if override_global:
                    return limiter.exempt(f)(*args, **kwargs)
                else:
                    return f(*args, **kwargs)
            else:
                # Apply custom limits
                return limiter.limit(";".join(limits), override_defaults=override_global)(f)(*args, **kwargs)

        return decorated_function

    return decorator


def init_security(app):
    """Initialize security settings for the application."""
    # Initialize the limiter
    LimiterManager.initialize(app)

    # Session security
    app.config.update(
        PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
