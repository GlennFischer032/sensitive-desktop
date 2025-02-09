from typing import Dict, Optional, Any, Tuple
from datetime import datetime, timedelta
import requests
from flask import session, current_app
import logging
from http import HTTPStatus
from pydantic import BaseModel, Field, ValidationError

logger = logging.getLogger(__name__)

class AuthResponse(BaseModel):
    """Schema for authentication response."""
    token: str = Field(..., description="JWT authentication token")
    is_admin: bool = Field(..., description="Admin status")
    username: str = Field(..., description="Username")

class AuthError(Exception):
    """Custom exception for authentication errors."""
    def __init__(self, message: str, status_code: int = HTTPStatus.UNAUTHORIZED):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

class RateLimitError(AuthError):
    """Exception for rate limit errors."""
    def __init__(self, retry_after: int):
        self.retry_after = retry_after
        super().__init__(
            f"Rate limit exceeded. Please try again in {retry_after} seconds.",
            HTTPStatus.TOO_MANY_REQUESTS
        )

def handle_auth_response(response: requests.Response) -> Tuple[Dict[str, Any], int]:
    """
    Handle authentication API response.
    
    Args:
        response: Response from auth API
        
    Returns:
        Tuple[Dict[str, Any], int]: Response data and status code
        
    Raises:
        AuthError: If authentication fails
        RateLimitError: If rate limited
        ValidationError: If response validation fails
    """
    try:
        if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
            retry_after = int(response.headers.get("Retry-After", 60))
            raise RateLimitError(retry_after)
            
        data = response.json()
        
        if response.status_code != HTTPStatus.OK:
            raise AuthError(
                data.get("error", "Authentication failed"),
                response.status_code
            )
            
        # Validate response data
        auth_data = AuthResponse(**data)
        return auth_data.model_dump(), HTTPStatus.OK
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error: {str(e)}")
        raise AuthError("Failed to connect to authentication service")
    except ValidationError as e:
        logger.error(f"Response validation error: {str(e)}")
        raise AuthError("Invalid response from authentication service")

def login(username: str, password: str) -> Tuple[Dict[str, Any], int]:
    """
    Authenticate user with credentials.
    
    Args:
        username: Username
        password: Password
        
    Returns:
        Tuple[Dict[str, Any], int]: Authentication response and status code
        
    Raises:
        AuthError: If authentication fails
        RateLimitError: If rate limited
    """
    try:
        response = requests.post(
            f"{current_app.config['API_URL']}/auth/login",
            json={"username": username, "password": password},
            headers={"Content-Type": "application/json"}
        )
        
        data, status_code = handle_auth_response(response)
        
        if status_code == HTTPStatus.OK:
            session["token"] = data["token"]
            session["is_admin"] = data["is_admin"]
            session["username"] = data["username"]
            session["logged_in"] = True
            
        return data, status_code
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise

def logout() -> None:
    """Clear user session."""
    session.clear()

def is_authenticated() -> bool:
    """Check if user is authenticated."""
    return session.get("logged_in", False)

def get_current_user() -> Optional[Dict[str, Any]]:
    """
    Get current authenticated user info.
    
    Returns:
        Optional[Dict[str, Any]]: User info if authenticated, None otherwise
    """
    if is_authenticated():
        return {
            "username": session["username"],
            "is_admin": session["is_admin"]
        }
    return None

def refresh_token() -> None:
    """
    Refresh authentication token.
    
    Raises:
        AuthError: If token refresh fails
        RateLimitError: If rate limited
    """
    try:
        if not is_authenticated():
            raise AuthError("Not authenticated")
            
        response = requests.post(
            f"{current_app.config['API_URL']}/auth/refresh",
            headers={
                "Authorization": f"Bearer {session['token']}",
                "Content-Type": "application/json"
            }
        )
        
        data, status_code = handle_auth_response(response)
        
        if status_code == HTTPStatus.OK:
            session["token"] = data["token"]
            
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        # Clear session on refresh failure
        logout()
        raise 