import pytest
import sys
import os
from http import HTTPStatus

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from core.exceptions import (
    APIError,
    ValidationError,
    DatabaseError,
    GuacamoleError,
    UserNotFoundError,
    UserAlreadyExistsError,
    AuthenticationError,
    AuthorizationError,
)


class TestAPIError:
    """Tests for the base APIError class."""

    def test_init_with_defaults(self):
        """Test initializing APIError with default values."""
        # Act
        error = APIError("Test error message")

        # Assert
        assert str(error) == "Test error message"
        assert error.message == "Test error message"
        assert error.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
        assert error.details == {}

    def test_init_with_custom_values(self):
        """Test initializing APIError with custom values."""
        # Arrange
        message = "Custom error message"
        status_code = HTTPStatus.BAD_REQUEST
        details = {"field": "username", "error": "Invalid username"}

        # Act
        error = APIError(message, status_code, details)

        # Assert
        assert str(error) == message
        assert error.message == message
        assert error.status_code == status_code
        assert error.details == details

    def test_to_dict(self):
        """Test converting APIError to dictionary."""
        # Arrange
        message = "Test error"
        details = {"code": "test_error"}
        error = APIError(message, HTTPStatus.BAD_REQUEST, details)

        # Act
        result = error.to_dict()

        # Assert
        assert result == {
            "error": "APIError",
            "message": message,
            "details": details,
        }


class TestValidationError:
    """Tests for ValidationError."""

    def test_init(self):
        """Test ValidationError initialization."""
        # Arrange
        message = "Validation failed"
        details = {"field": "username", "error": "Required field missing"}

        # Act
        error = ValidationError(message, details)

        # Assert
        assert str(error) == message
        assert error.message == message
        assert error.status_code == HTTPStatus.BAD_REQUEST
        assert error.details == details

    def test_to_dict(self):
        """Test ValidationError to_dict method."""
        # Arrange
        error = ValidationError("Invalid input", {"field": "email"})

        # Act
        result = error.to_dict()

        # Assert
        assert result == {
            "error": "ValidationError",
            "message": "Invalid input",
            "details": {"field": "email"},
        }


class TestDatabaseError:
    """Tests for DatabaseError."""

    def test_init(self):
        """Test DatabaseError initialization."""
        # Act
        error = DatabaseError("Database connection failed")

        # Assert
        assert str(error) == "Database connection failed"
        assert error.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
        assert error.details == {}


class TestGuacamoleError:
    """Tests for GuacamoleError."""

    def test_init(self):
        """Test GuacamoleError initialization."""
        # Act
        error = GuacamoleError("Failed to connect to Guacamole")

        # Assert
        assert str(error) == "Failed to connect to Guacamole"
        assert error.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
        assert error.details == {}


class TestUserNotFoundError:
    """Tests for UserNotFoundError."""

    def test_init(self):
        """Test UserNotFoundError initialization."""
        # Act
        error = UserNotFoundError("User not found")

        # Assert
        assert str(error) == "User not found"
        assert error.status_code == HTTPStatus.NOT_FOUND
        assert error.details == {}


class TestUserAlreadyExistsError:
    """Tests for UserAlreadyExistsError."""

    def test_init(self):
        """Test UserAlreadyExistsError initialization."""
        # Act
        error = UserAlreadyExistsError("User already exists")

        # Assert
        assert str(error) == "User already exists"
        assert error.status_code == HTTPStatus.CONFLICT
        assert error.details == {}


class TestAuthenticationError:
    """Tests for AuthenticationError."""

    def test_init(self):
        """Test AuthenticationError initialization."""
        # Act
        error = AuthenticationError("Authentication failed")

        # Assert
        assert str(error) == "Authentication failed"
        assert error.status_code == HTTPStatus.UNAUTHORIZED
        assert error.details == {}


class TestAuthorizationError:
    """Tests for AuthorizationError."""

    def test_init(self):
        """Test AuthorizationError initialization."""
        # Act
        error = AuthorizationError("Insufficient permissions")

        # Assert
        assert str(error) == "Insufficient permissions"
        assert error.status_code == HTTPStatus.FORBIDDEN
        assert error.details == {}
