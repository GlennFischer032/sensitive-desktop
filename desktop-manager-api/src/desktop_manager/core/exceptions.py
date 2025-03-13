from http import HTTPStatus
from typing import Any, Dict, Optional


class APIError(Exception):
    """Base exception class for API errors."""

    def __init__(
        self,
        message: str,
        status_code: int = HTTPStatus.INTERNAL_SERVER_ERROR,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Initialize the API error.

        Args:
            message: Error message
            status_code: HTTP status code
            details: Additional error details
        """
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary format."""
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            "details": self.details,
        }


class ValidationError(APIError):
    """Raised when input validation fails."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, HTTPStatus.BAD_REQUEST, details)


class DatabaseError(APIError):
    """Raised when database operations fail."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, HTTPStatus.INTERNAL_SERVER_ERROR, details)


class GuacamoleError(APIError):
    """Raised when Guacamole operations fail."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, HTTPStatus.INTERNAL_SERVER_ERROR, details)


class UserNotFoundError(APIError):
    """Raised when a requested user is not found."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, HTTPStatus.NOT_FOUND, details)


class UserAlreadyExistsError(APIError):
    """Raised when attempting to create a user that already exists."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, HTTPStatus.CONFLICT, details)


class AuthenticationError(APIError):
    """Raised when authentication fails."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, HTTPStatus.UNAUTHORIZED, details)


class AuthorizationError(APIError):
    """Raised when authorization fails."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, HTTPStatus.FORBIDDEN, details)
