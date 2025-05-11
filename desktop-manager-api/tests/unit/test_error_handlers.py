import pytest
import sys
import os
from http import HTTPStatus
from unittest.mock import patch, MagicMock
from pydantic import BaseModel, ValidationError, Field
from flask import Flask

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from utils.error_handlers import format_validation_error, handle_validation_error


# Sample Pydantic models for testing
class User(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., pattern=r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
    age: int = Field(..., ge=18)


@pytest.fixture
def app():
    """Create a Flask application for testing."""
    app = Flask(__name__)
    app.config["TESTING"] = True
    return app


class TestErrorHandlers:
    """Tests for error handler utilities."""

    def test_format_validation_error_missing_field(self):
        """Test formatting error for missing field."""
        # Arrange
        try:
            User(username="bob", age=20)  # Missing email
            pytest.fail("Should have raised ValidationError")
        except ValidationError as e:
            # Act
            formatted = format_validation_error(e)

            # Assert
            assert "error" in formatted
            assert "details" in formatted
            assert "email" in formatted["details"]
            assert any("required" in msg.lower() for msg in formatted["details"]["email"])

    def test_format_validation_error_too_short(self):
        """Test formatting error for string too short."""
        # Arrange
        try:
            User(username="a", email="test@example.com", age=20)  # Username too short
            pytest.fail("Should have raised ValidationError")
        except ValidationError as e:
            # Act
            formatted = format_validation_error(e)

            # Assert
            assert "details" in formatted
            assert "username" in formatted["details"]
            assert any("at least 3 characters" in msg for msg in formatted["details"]["username"])

    def test_format_validation_error_too_long(self):
        """Test formatting error for string too long."""
        # Arrange
        try:
            User(username="a" * 51, email="test@example.com", age=20)  # Username too long
            pytest.fail("Should have raised ValidationError")
        except ValidationError as e:
            # Act
            formatted = format_validation_error(e)

            # Assert
            assert "details" in formatted
            assert "username" in formatted["details"]
            assert any("not exceed 50 characters" in msg for msg in formatted["details"]["username"])

    def test_format_validation_error_invalid_pattern(self):
        """Test formatting error for invalid pattern (email)."""
        # Arrange
        try:
            User(username="bob", email="not-an-email", age=20)  # Invalid email
            pytest.fail("Should have raised ValidationError")
        except ValidationError as e:
            # Act
            formatted = format_validation_error(e)

            # Assert
            assert "details" in formatted
            assert "email" in formatted["details"]

    def test_format_validation_error_invalid_type(self):
        """Test formatting error for invalid type."""
        # Arrange
        try:
            User(username="bob", email="test@example.com", age="not-a-number")  # Age is not a number
            pytest.fail("Should have raised ValidationError")
        except ValidationError as e:
            # Act
            formatted = format_validation_error(e)

            # Assert
            assert "details" in formatted
            assert "age" in formatted["details"]

    def test_format_validation_error_multiple_errors(self):
        """Test formatting multiple validation errors."""
        # Arrange
        try:
            User(username="a", email="not-an-email", age=10)  # Multiple errors
            pytest.fail("Should have raised ValidationError")
        except ValidationError as e:
            # Act
            formatted = format_validation_error(e)

            # Assert
            assert "details" in formatted
            assert "username" in formatted["details"]
            assert "email" in formatted["details"]
            assert "age" in formatted["details"]

    def test_handle_validation_error(self, app):
        """Test the validation error handler."""
        # Arrange
        try:
            User(username="bob", age=20)  # Missing email
            pytest.fail("Should have raised ValidationError")
        except ValidationError as e:
            # Need Flask application context
            with app.app_context():
                # Act
                response, status_code = handle_validation_error(e)

                # Assert
                assert status_code == HTTPStatus.BAD_REQUEST
                assert "error" in response.get_json()
                assert "details" in response.get_json()
                assert "email" in response.get_json()["details"]
