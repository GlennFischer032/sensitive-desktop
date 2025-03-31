"""Unit tests for error handlers."""

import pytest
from pydantic import BaseModel, ValidationError, Field, model_validator
from flask import Flask, Response
import json
from http import HTTPStatus

from desktop_manager.api.utils.error_handlers import format_validation_error, handle_validation_error


class TestModel(BaseModel):
    """Test model for validation errors."""

    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., pattern=r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
    age: int = Field(..., ge=18, le=120)


def test_format_validation_error():
    """Test format_validation_error function."""
    # Create a ValidationError
    try:
        TestModel(username="a", email="test@example.com", age=30)
        pytest.fail("Should have raised ValidationError")
    except ValidationError as e:
        # Call format_validation_error
        error_dict = format_validation_error(e)

        # Check the error format
        assert "error" in error_dict
        assert error_dict["error"] == "Validation Error"

        assert "details" in error_dict
        details = error_dict["details"]

        # Should have an error for username
        assert "username" in details


def test_format_validation_error_missing_field():
    """Test format_validation_error with missing field."""
    # Create a ValidationError with missing field
    try:
        TestModel(username="test")
        pytest.fail("Should have raised ValidationError")
    except ValidationError as e:
        error_dict = format_validation_error(e)

        # Check the error format
        assert "error" in error_dict
        assert error_dict["error"] == "Validation Error"

        assert "details" in error_dict
        details = error_dict["details"]

        # Should have errors for email and age
        assert "email" in details
        assert "age" in details

        # Check the error messages
        assert "This field is required" in details["email"][0]
        assert "This field is required" in details["age"][0]


def test_format_validation_error_string_too_short():
    """Test format_validation_error with string too short."""
    # Create a ValidationError with too short string
    try:
        TestModel(username="a", email="test@example.com", age=30)
        pytest.fail("Should have raised ValidationError")
    except ValidationError as e:
        error_dict = format_validation_error(e)

        # Check the error format
        assert "error" in error_dict
        assert error_dict["error"] == "Validation Error"

        assert "details" in error_dict
        details = error_dict["details"]

        # Should have an error for username
        assert "username" in details

        # Check the error message for min_length
        assert "Must be at least 3 characters long" in details["username"][0]


def test_format_validation_error_string_too_long():
    """Test format_validation_error with string too long."""
    # Create a ValidationError with too long string
    try:
        TestModel(username="a" * 51, email="test@example.com", age=30)
        pytest.fail("Should have raised ValidationError")
    except ValidationError as e:
        error_dict = format_validation_error(e)

        # Check the error format
        assert "error" in error_dict
        assert error_dict["error"] == "Validation Error"

        assert "details" in error_dict
        details = error_dict["details"]

        # Should have an error for username
        assert "username" in details

        # Check the error message for max_length
        assert "Must not exceed 50 characters" in details["username"][0]


def test_format_validation_error_number_out_of_range():
    """Test format_validation_error with number out of range."""
    # Create a ValidationError with number out of range
    try:
        TestModel(username="test", email="test@example.com", age=0)
        pytest.fail("Should have raised ValidationError")
    except ValidationError as e:
        error_dict = format_validation_error(e)

        # Check the error format
        assert "error" in error_dict
        assert error_dict["error"] == "Validation Error"

        assert "details" in error_dict
        details = error_dict["details"]

        # Should have an error for age
        assert "age" in details


def test_format_validation_error_multiple_errors():
    """Test format_validation_error with multiple errors."""
    # Create a ValidationError with multiple errors
    try:
        TestModel(username="a", age=-1)
        pytest.fail("Should have raised ValidationError")
    except ValidationError as e:
        error_dict = format_validation_error(e)

        # Check the error format
        assert "error" in error_dict
        assert error_dict["error"] == "Validation Error"

        assert "details" in error_dict
        details = error_dict["details"]

        # Should have errors for username, email, and age
        assert "username" in details
        assert "email" in details
        assert "age" in details


def test_format_validation_error_with_general_error():
    """Test format_validation_error with a general error."""
    # Create a ValidationError with a general error
    class LimitedModel(BaseModel):
        """Test model with a validator that raises an error not tied to a specific field."""

        value: str

        @model_validator(mode='before')
        @classmethod
        def validate_model(cls, data):
            """Always raise an error not tied to a specific field."""
            # In Pydantic v2, we need to use ValueError directly instead of ErrorWrapper
            raise ValueError("General validation error")

    # Create a Flask app for context
    app = Flask(__name__)

    with app.app_context():
        try:
            LimitedModel(value="any value")
            pytest.fail("Should have raised ValidationError")
        except ValidationError as e:
            # Call format_validation_error
            error_dict = format_validation_error(e)

            # Check result
            assert "error" in error_dict
            assert error_dict["error"] == "Validation Error"
            assert "details" in error_dict


def test_handle_validation_error():
    """Test handle_validation_error function."""
    # Create a Flask app for context
    app = Flask(__name__)

    with app.app_context():
        # Create a ValidationError
        try:
            TestModel(username="a", email="test@example.com", age=30)
            pytest.fail("Should have raised ValidationError")
        except ValidationError as e:
            # Call handle_validation_error
            response, status_code = handle_validation_error(e)

            # Check response
            assert status_code == HTTPStatus.BAD_REQUEST
            assert isinstance(response, Response)

            # Convert response to dict for checking
            response_data = json.loads(response.get_data(as_text=True))
            assert "error" in response_data
            assert "details" in response_data
            assert "username" in response_data["details"]
