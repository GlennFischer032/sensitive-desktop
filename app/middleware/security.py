import logging
import time
from datetime import timedelta
from functools import wraps
from http import HTTPStatus
from typing import Callable, Dict, Optional

from flask import current_app, render_template, request, session

logger = logging.getLogger(__name__)


class RateLimiter:
    """Enhanced in-memory rate limiter with configurable limits."""

    def __init__(self):
        self.requests: Dict[str, list] = {}
        self.cleanup_interval = 3600  # Cleanup old entries every hour
        self.last_cleanup = time.time()
        self.default_limits = {
            "1s": (10, 1),  # 10 requests per second
            "1m": (30, 60),  # 30 requests per minute
            "1h": (1000, 3600),  # 1000 requests per hour
        }

    def is_rate_limited(self, key: str, limits: Optional[Dict[str, tuple]] = None) -> tuple[bool, Optional[int]]:
        """
        Check if a key is rate limited.

        Args:
            key: The key to check (usually IP address)
            limits: Optional custom limits override

        Returns:
            tuple: (is_limited, retry_after)
        """
        now = time.time()

        # Cleanup old entries if needed
        if now - self.last_cleanup > self.cleanup_interval:
            self._cleanup()
            self.last_cleanup = now

        if key not in self.requests:
            self.requests[key] = []

        # Use provided limits or defaults
        check_limits = limits or self.default_limits

        # Check all time windows
        for _, (limit, window) in check_limits.items():
            # Remove old requests for this window
            window_requests = [t for t in self.requests[key] if now - t < window]

            if len(window_requests) >= limit:
                retry_after = int(min(window_requests) + window - now)
                return True, retry_after

        # Add current request timestamp
        self.requests[key].append(now)
        return False, None

    def _cleanup(self):
        """Remove old entries to prevent memory growth."""
        now = time.time()
        max_window = max(window for _, (_, window) in self.default_limits.items())

        for key in list(self.requests.keys()):
            self.requests[key] = [t for t in self.requests[key] if now - t < max_window]
            if not self.requests[key]:
                del self.requests[key]


# Global rate limiter instance
rate_limiter = RateLimiter()


def _build_custom_limits(
    requests_per_second: Optional[int],
    requests_per_minute: Optional[int],
    requests_per_hour: Optional[int],
) -> Dict[str, tuple]:
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
    requests_per_second: Optional[int] = None,
    requests_per_minute: Optional[int] = None,
    requests_per_hour: Optional[int] = None,
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


def admin_required(f: Callable) -> Callable:
    """Require admin privileges for route."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("is_admin"):
            return {
                "error": "Forbidden",
                "message": "Admin privileges required",
            }, HTTPStatus.FORBIDDEN

        return f(*args, **kwargs)

    return decorated_function


def init_security(app):
    """Initialize security settings for the application."""
    # Session security
    app.config.update(
        PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
