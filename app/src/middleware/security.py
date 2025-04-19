import logging
from collections.abc import Callable
from datetime import datetime, timedelta
from functools import wraps
from http import HTTPStatus

from clients.factory import client_factory
from flask import current_app, render_template, request

logger = logging.getLogger(__name__)


class RateLimiter:
    def __init__(self):
        self.default_limits = {
            "1s": (10, 1),  # 10 requests per second
            "1m": (30, 60),  # 30 requests per minute
            "1h": (1000, 3600),  # 1000 requests per hour
        }
        self._redis = None
        self._app = None

    def is_rate_limited(self, key: str, limits: dict[str, tuple] | None = None) -> tuple[bool, int | None]:
        """
        Check if a key is rate limited.

        Args:
            key: The key to check (usually IP address)
            limits: Optional custom limits override

        Returns:
            tuple: (is_limited, retry_after)
        """
        # Use the RedisClient's is_rate_limited method directly
        now = datetime.now().timestamp()
        redis_client = client_factory.get_redis_client()

        # Use provided limits or defaults
        check_limits = limits or self.default_limits

        # Redis key prefix for rate limiting
        prefix = "rate_limit:"

        # Check all time windows
        for window_name, (limit, window) in check_limits.items():
            # Create a key specific to this window
            window_key = f"{prefix}{key}:{window_name}"

            # Get current count for this window
            current_count = 0

            # Use Redis sorted set with score as timestamp
            # First, remove expired timestamps (older than window)
            redis_client.zremrangebyscore(window_key, 0, now - window)

            # Count remaining timestamps in the window
            current_count = redis_client.zcard(window_key)

            # Check if limit exceeded
            if current_count >= limit:
                # Get oldest timestamp to calculate retry-after
                oldest = redis_client.zrange(window_key, 0, 0, withscores=True)
                if oldest:
                    retry_after = int(oldest[0][1] + window - now)
                    return True, retry_after
                return True, window  # Fallback if no timestamps found

        # Add current timestamp to all window keys and set expiry
        pipeline = redis_client.pipeline()
        for window_name, (_, window) in check_limits.items():
            window_key = f"{prefix}{key}:{window_name}"
            pipeline.zadd(window_key, {str(now): now})
            pipeline.expire(window_key, window)  # Set TTL on the key
        pipeline.execute()

        return False, None


# Global rate limiter instance
rate_limiter = RateLimiter()


def _build_custom_limits(
    requests_per_second: int | None,
    requests_per_minute: int | None,
    requests_per_hour: int | None,
) -> dict[str, tuple]:
    """Build custom rate limits dictionary from individual settings."""
    custom_limits = {}
    if requests_per_second is not None:
        custom_limits["1s"] = (requests_per_second, 1)
    if requests_per_minute is not None:
        custom_limits["1m"] = (requests_per_minute, 60)
    if requests_per_hour is not None:
        custom_limits["1h"] = (requests_per_hour, 3600)
    return custom_limits


def rate_limit(
    requests_per_second: int | None = None,
    requests_per_minute: int | None = None,
    requests_per_hour: int | None = None,
    override_global: bool = True,
):
    """
    Enhanced rate limiting decorator with multiple time windows.

    Args:
        requests_per_second: Maximum requests per second
        requests_per_minute: Maximum requests per minute
        requests_per_hour: Maximum requests per hour
        override_global: If True, only these limits are applied.
                        If False, these limits are checked with global limits.
    """

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client IP
            client_ip = request.remote_addr

            # Build custom limits
            custom_limits = _build_custom_limits(requests_per_second, requests_per_minute, requests_per_hour)

            # If not overriding global limits, merge with defaults
            if not override_global and custom_limits:
                default_limits = {
                    "1s": (current_app.config["RATE_LIMIT_DEFAULT_SECOND"], 1),
                    "1m": (current_app.config["RATE_LIMIT_DEFAULT_MINUTE"], 60),
                    "1h": (current_app.config["RATE_LIMIT_DEFAULT_HOUR"], 3600),
                }
                # Use the more restrictive limit for each window
                for window, (limit, duration) in default_limits.items():
                    if window in custom_limits:
                        custom_limits[window] = (
                            min(custom_limits[window][0], limit),
                            duration,
                        )
                    else:
                        custom_limits[window] = (limit, duration)

            # Check rate limit
            endpoint_key = f"{client_ip}:{request.endpoint}"
            is_limited, retry_after = rate_limiter.is_rate_limited(
                endpoint_key,  # Separate limits per endpoint
                custom_limits if custom_limits else None,
            )

            if is_limited:
                logger.warning(
                    "Rate limit exceeded for IP: %s on endpoint: %s",
                    client_ip,
                    request.endpoint,
                )

                # Handle AJAX requests
                if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                    return {
                        "error": "Too many requests",
                        "message": f"Please try again in {retry_after} seconds",
                    }, HTTPStatus.TOO_MANY_REQUESTS

                # Handle regular requests
                return (
                    render_template(
                        "errors/429.html",
                        error={
                            "message": "Too many requests. Please try again later.",
                            "retry_after": retry_after,
                        },
                    ),
                    HTTPStatus.TOO_MANY_REQUESTS,
                )

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def init_security(app):
    """Initialize security settings for the application."""
    # Session security
    app.config.update(
        PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
