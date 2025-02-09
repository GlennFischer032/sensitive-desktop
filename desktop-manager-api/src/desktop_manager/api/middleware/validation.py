from functools import wraps
from flask import request, jsonify
from typing import Callable, Dict, Any, Optional, List, Union
from pydantic import BaseModel, ValidationError
import re
import logging
from http import HTTPStatus
from desktop_manager.core.exceptions import ValidationError as APIValidationError

logger = logging.getLogger(__name__)

class RequestValidationConfig:
    """Configuration for request validation."""
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB
    ALLOWED_CONTENT_TYPES = {
        "application/json",
        "multipart/form-data",
        "application/x-www-form-urlencoded"
    }
    ALLOWED_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
    
    # Security headers that should be present
    REQUIRED_SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
    }

def validate_content_length(max_length: int = RequestValidationConfig.MAX_CONTENT_LENGTH):
    """Validate request content length."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            content_length = request.content_length
            if content_length and content_length > max_length:
                return jsonify({
                    "error": "Request entity too large",
                    "max_size": f"{max_length/1024/1024}MB"
                }), HTTPStatus.REQUEST_ENTITY_TOO_LARGE
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_content_type(allowed_types: Optional[set] = None):
    """Validate request content type."""
    if allowed_types is None:
        allowed_types = RequestValidationConfig.ALLOWED_CONTENT_TYPES
        
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method in ["POST", "PUT", "PATCH"]:
                content_type = request.content_type
                if not content_type:
                    return jsonify({
                        "error": "Content-Type header is required"
                    }), HTTPStatus.BAD_REQUEST
                    
                base_content_type = content_type.split(";")[0].lower()
                if base_content_type not in allowed_types:
                    return jsonify({
                        "error": "Unsupported content type",
                        "allowed_types": list(allowed_types)
                    }), HTTPStatus.UNSUPPORTED_MEDIA_TYPE
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_json_schema(schema: BaseModel):
    """Validate request JSON data against a Pydantic schema."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                if request.is_json:
                    data = request.get_json()
                    validated_data = schema(**data)
                    # Attach validated data to request
                    request.validated_data = validated_data
                return f(*args, **kwargs)
            except ValidationError as e:
                return jsonify({
                    "error": "Validation error",
                    "details": e.errors()
                }), HTTPStatus.BAD_REQUEST
        return decorated_function
    return decorator

def sanitize_headers():
    """Sanitize and validate request headers."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check for security headers
            response = f(*args, **kwargs)
            
            # Add security headers if response is a tuple
            if isinstance(response, tuple):
                response_obj, status_code = response
                headers = response_obj.headers
            else:
                headers = response.headers
                
            # Add required security headers
            for header, value in RequestValidationConfig.REQUIRED_SECURITY_HEADERS.items():
                headers[header] = value
                
            return response
        return decorated_function
    return decorator

def validate_path_params(pattern: str):
    """Validate URL path parameters against a regex pattern."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            for param_name, param_value in kwargs.items():
                if not re.match(pattern, str(param_value)):
                    return jsonify({
                        "error": f"Invalid path parameter: {param_name}",
                        "pattern": pattern
                    }), HTTPStatus.BAD_REQUEST
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_query_params(allowed_params: set):
    """Validate query parameters."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            query_params = set(request.args.keys())
            invalid_params = query_params - allowed_params
            if invalid_params:
                return jsonify({
                    "error": "Invalid query parameters",
                    "invalid_params": list(invalid_params),
                    "allowed_params": list(allowed_params)
                }), HTTPStatus.BAD_REQUEST
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def comprehensive_validation(
    schema: Optional[BaseModel] = None,
    max_content_length: Optional[int] = None,
    allowed_content_types: Optional[set] = None,
    path_pattern: Optional[str] = None,
    allowed_query_params: Optional[set] = None
):
    """Comprehensive request validation combining all validators."""
    def decorator(f: Callable) -> Callable:
        # Apply validators in order
        if max_content_length:
            f = validate_content_length(max_content_length)(f)
        if allowed_content_types:
            f = validate_content_type(allowed_content_types)(f)
        if schema:
            f = validate_json_schema(schema)(f)
        if path_pattern:
            f = validate_path_params(path_pattern)(f)
        if allowed_query_params:
            f = validate_query_params(allowed_query_params)(f)
            
        f = sanitize_headers()(f)
        
        @wraps(f)
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)
        return decorated_function
    return decorator 