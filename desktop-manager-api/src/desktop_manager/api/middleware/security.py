import logging
import time
from typing import Any

import bleach


logger = logging.getLogger(__name__)

# Rate limiting configuration
RATE_LIMIT_WINDOWS: dict[str, int] = {
    "1s": 1,  # 1 second window
    "1m": 60,  # 1 minute window
    "1h": 3600,  # 1 hour window
}


class RateLimiter:
    """Rate limiter implementation using sliding window."""

    def __init__(self):
        self.requests: dict[str, list[float]] = {}

    def is_rate_limited(self, key: str, max_requests: int, window: float) -> bool:
        """Check if a key is rate limited.

        Args:
            key: The key to check (e.g., IP address)
            max_requests: Maximum requests allowed in window
            window: Time window in seconds

        Returns:
            bool: True if rate limited, False otherwise
        """
        now = time.time()

        # Initialize request list for key if not exists
        if key not in self.requests:
            self.requests[key] = []

        # Remove old requests outside window
        self.requests[key] = [req_time for req_time in self.requests[key] if now - req_time <= window]

        # Check if rate limited
        if len(self.requests[key]) >= max_requests:
            return True

        # Add current request
        self.requests[key].append(now)
        return False


# Global rate limiter instance
rate_limiter = RateLimiter()


def sanitize_input(data: Any) -> Any:
    """Recursively sanitize input data.

    Args:
        data: Input data to sanitize

    Returns:
        Sanitized data
    """
    if isinstance(data, str):
        return bleach.clean(data)
    elif isinstance(data, dict):
        return {k: sanitize_input(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_input(item) for item in data]
    return data
