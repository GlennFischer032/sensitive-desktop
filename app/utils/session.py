import logging
from datetime import datetime, timedelta
from functools import wraps
from http import HTTPStatus
from typing import Any, Dict, Optional

from flask import request, session

from app.auth.auth import AuthError, is_authenticated, refresh_token

logger = logging.getLogger(__name__)


class SessionConfig:
    """Session configuration constants."""

    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_REFRESH_EACH_REQUEST = True


def configure_session(app):
    """
    Configure session settings for the application.

    Args:
        app: Flask application instance
    """
    app.config.update(
        PERMANENT_SESSION_LIFETIME=SessionConfig.PERMANENT_SESSION_LIFETIME,
        SESSION_COOKIE_SECURE=SessionConfig.SESSION_COOKIE_SECURE,
        SESSION_COOKIE_HTTPONLY=SessionConfig.SESSION_COOKIE_HTTPONLY,
        SESSION_COOKIE_SAMESITE=SessionConfig.SESSION_COOKIE_SAMESITE,
        SESSION_REFRESH_EACH_REQUEST=SessionConfig.SESSION_REFRESH_EACH_REQUEST,
    )


def session_manager(f):
    """
    Decorator for managing session lifecycle.

    This decorator handles:
    - Session validation
    - Token refresh
    - Session cleanup on errors
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # Check if session needs refresh
            if is_authenticated():
                try:
                    refresh_token()
                except AuthError:
                    # Clear invalid session
                    session.clear()
                    return {
                        "error": "Session expired",
                        "message": "Please log in again",
                    }, HTTPStatus.UNAUTHORIZED

            return f(*args, **kwargs)

        except Exception as e:
            logger.error(f"Session error: {str(e)}")
            session.clear()
            return {
                "error": "Session error",
                "message": str(e),
            }, HTTPStatus.INTERNAL_SERVER_ERROR

    return decorated_function


def get_session_info() -> Dict[str, Any]:
    """
    Get current session information.

    Returns:
        Dict[str, Any]: Session information including user data and expiry
    """
    if not is_authenticated():
        return {"authenticated": False, "expires_in": None}

    # Calculate session expiry
    now = datetime.utcnow()
    session_end = now + SessionConfig.PERMANENT_SESSION_LIFETIME
    expires_in = int((session_end - now).total_seconds())

    return {
        "authenticated": True,
        "username": session.get("username"),
        "is_admin": session.get("is_admin", False),
        "expires_in": expires_in,
    }


def end_session() -> None:
    """End current session and clear data."""
    try:
        session.clear()
    except Exception as e:
        logger.error(f"Error ending session: {str(e)}")
        raise


def validate_session_token() -> Optional[str]:
    """
    Validate and return session token.

    Returns:
        Optional[str]: Valid session token or None
    """
    if not is_authenticated():
        return None

    token = session.get("token")
    if not token:
        session.clear()
        return None

    return token
