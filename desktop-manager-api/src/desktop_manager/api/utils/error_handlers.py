from typing import Dict, Any
from pydantic import ValidationError
from flask import jsonify
from http import HTTPStatus

def format_validation_error(error: ValidationError) -> Dict[str, Any]:
    """
    Format Pydantic validation errors into a user-friendly format.
    
    Args:
        error: The Pydantic ValidationError
        
    Returns:
        Dict containing formatted error messages
    """
    errors = {}
    for e in error.errors():
        field = e['loc'][0] if e['loc'] else 'general'
        if field not in errors:
            errors[field] = []
        
        # Convert error messages to user-friendly format
        msg = e['msg']
        if 'string_too_short' in str(e['type']):
            min_length = e['ctx']['min_length']
            msg = f"Must be at least {min_length} characters long"
        elif 'string_too_long' in str(e['type']):
            max_length = e['ctx']['max_length']
            msg = f"Must not exceed {max_length} characters"
        elif 'missing' in str(e['type']):
            msg = "This field is required"
            
        errors[field].append(msg)
    
    return {
        'error': 'Validation Error',
        'details': errors
    }

def handle_validation_error(error: ValidationError):
    """
    Handle Pydantic validation errors and return formatted response.
    
    Args:
        error: The Pydantic ValidationError
        
    Returns:
        Tuple of JSON response and HTTP status code
    """
    return jsonify(format_validation_error(error)), HTTPStatus.BAD_REQUEST 