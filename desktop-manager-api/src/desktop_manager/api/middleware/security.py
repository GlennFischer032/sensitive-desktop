from functools import wraps
from flask import request, jsonify, current_app
from werkzeug.datastructures import Headers
from typing import Callable, Dict, Any, Optional, List, Union
import time
from datetime import datetime, timedelta
import re
import bleach
from http import HTTPStatus
import logging
from desktop_manager.core.exceptions import ValidationError

logger = logging.getLogger(__name__)

# Rate limiting configuration
RATE_LIMIT_WINDOWS: Dict[str, int] = {
    "1s": 1,      # 1 second window
    "1m": 60,     # 1 minute window
    "1h": 3600,   # 1 hour window
}

class RateLimiter:
    """Rate limiter implementation using sliding window."""
    
    def __init__(self):
        self.requests: Dict[str, List[float]] = {}
    
    def is_rate_limited(
        self,
        key: str,
        max_requests: int,
        window: int
    ) -> bool:
        """
        Check if a key is rate limited.
        
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
        self.requests[key] = [
            req_time for req_time in self.requests[key]
            if now - req_time <= window
        ]
        
        # Check if rate limited
        if len(self.requests[key]) >= max_requests:
            return True
            
        # Add current request
        self.requests[key].append(now)
        return False

# Global rate limiter instance
rate_limiter = RateLimiter()

def rate_limit(
    requests_per_second: int = 10,
    requests_per_minute: int = 100,
    requests_per_hour: int = 1000
):
    """
    Rate limiting decorator.
    
    Args:
        requests_per_second: Max requests per second
        requests_per_minute: Max requests per minute
        requests_per_hour: Max requests per hour
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client IP
            client_ip = request.remote_addr
            
            # Check rate limits for different windows
            limits = [
                (requests_per_second, RATE_LIMIT_WINDOWS["1s"]),
                (requests_per_minute, RATE_LIMIT_WINDOWS["1m"]),
                (requests_per_hour, RATE_LIMIT_WINDOWS["1h"])
            ]
            
            for max_requests, window in limits:
                if rate_limiter.is_rate_limited(
                    f"{client_ip}:{window}",
                    max_requests,
                    window
                ):
                    return jsonify({
                        "error": "Rate limit exceeded",
                        "retry_after": window
                    }), HTTPStatus.TOO_MANY_REQUESTS
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def sanitize_input(data: Any) -> Any:
    """
    Recursively sanitize input data.
    
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

def validate_request_data():
    """Request data validation decorator."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Sanitize input data
                if request.is_json:
                    request.json = sanitize_input(request.get_json())
                
                # Validate content type for POST/PUT/PATCH
                if request.method in ["POST", "PUT", "PATCH"]:
                    if not request.is_json:
                        raise ValidationError(
                            "Content-Type must be application/json",
                            {"content_type": ["Invalid content type"]}
                        )
                
                return f(*args, **kwargs)
            except Exception as e:
                logger.error(f"Request validation error: {str(e)}")
                return jsonify({
                    "error": "Validation Error",
                    "message": str(e)
                }), HTTPStatus.BAD_REQUEST
        return decorated_function
    return decorator

def setup_cors(response):
    """
    Set up CORS headers for response.
    
    Args:
        response: Flask response object
        
    Returns:
        Response with CORS headers
    """
    # Get allowed origins from config
    allowed_origins = current_app.config.get(
        "CORS_ALLOWED_ORIGINS",
        ["http://localhost:5000"]
    )
    
    # Get request origin
    origin = request.headers.get("Origin")
    
    # Set CORS headers if origin is allowed
    if origin in allowed_origins:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Max-Age"] = "3600"
    
    return response 