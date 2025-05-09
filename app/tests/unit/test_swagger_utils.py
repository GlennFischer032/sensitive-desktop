"""
This module contains unit tests for the swagger utilities.
"""
import pytest
from unittest.mock import MagicMock, patch
from flask import Blueprint, Flask
import inspect

from utils.swagger import swag_from_doc, auto_document_blueprint


def test_swag_from_doc_preserves_function():
    """
    GIVEN a function
    WHEN decorated with swag_from_doc
    THEN check that the function name and docstring are preserved
    """

    def test_func():
        """Test docstring with swagger
        ---
        tags:
          - Test
        responses:
          200:
            description: Success
        """
        return "result"

    decorated_func = swag_from_doc(test_func)

    # Check that function attributes are preserved
    assert decorated_func.__name__ == test_func.__name__
    assert decorated_func.__doc__ == test_func.__doc__

    # Check that the function still works
    assert decorated_func() == "result"


class CustomMockBlueprint:
    """Custom mock blueprint for testing purposes."""

    def __init__(self):
        self.view_functions = {}

    def add_view_function(self, endpoint, func):
        """Add a view function to the mock blueprint."""
        self.view_functions[endpoint] = func


def test_auto_document_blueprint():
    """
    GIVEN a blueprint with view functions that have swagger docstrings
    WHEN auto_document_blueprint is called
    THEN check that the functions are marked as documented
    """
    # Create a mock blueprint
    bp = CustomMockBlueprint()

    # Create a view function with a swagger docstring
    def test_view():
        """Test view function
        ---
        tags:
          - Test
        responses:
          200:
            description: Success
        """
        return "test"

    # Create a view function without a swagger docstring
    def no_swagger_view():
        """Test view function without swagger"""
        return "no swagger"

    # Add view functions to the blueprint
    bp.add_view_function("test_view", test_view)
    bp.add_view_function("no_swagger_view", no_swagger_view)

    # Mock the getdoc function to return the actual docstrings
    with patch("utils.swagger.getdoc", side_effect=lambda f: f.__doc__):
        # Call the function
        auto_document_blueprint(bp, "Test")

    # Check that the function with swagger is marked as documented
    assert hasattr(test_view, "_swag_documented")
    assert test_view._swag_documented is True

    # Check that the function without swagger is not marked
    assert not hasattr(no_swagger_view, "_swag_documented")


def test_auto_document_blueprint_no_docstring():
    """
    GIVEN a blueprint with view functions that have no docstrings
    WHEN auto_document_blueprint is called
    THEN check that the functions are not marked as documented
    """
    # Create a mock blueprint
    bp = CustomMockBlueprint()

    # Create a view function without a docstring
    def no_doc_view():
        return "no doc"

    # Add view function to the blueprint
    bp.add_view_function("no_doc_view", no_doc_view)

    # Mock the getdoc function to return None (no docstring)
    with patch("utils.swagger.getdoc", return_value=None):
        # Call the function
        auto_document_blueprint(bp, "Test")

    # Check that the function is not marked as documented
    assert not hasattr(no_doc_view, "_swag_documented")


def test_auto_document_blueprint_already_documented():
    """
    GIVEN a blueprint with view functions that are already documented
    WHEN auto_document_blueprint is called
    THEN check that the functions retain their documentation attribute
    """
    # Create a mock blueprint
    bp = CustomMockBlueprint()

    # Create a view function with a swagger docstring
    def already_documented_view():
        """Test view function
        ---
        tags:
          - Test
        responses:
          200:
            description: Success
        """
        return "already documented"

    # Mark the function as already documented
    already_documented_view._swag_documented = True

    # Add view function to the blueprint
    bp.add_view_function("already_documented_view", already_documented_view)

    # Mock the getdoc function
    with patch("utils.swagger.getdoc", side_effect=lambda f: f.__doc__):
        # Call the function
        auto_document_blueprint(bp, "Test")

    # Check that the function is still marked as documented
    assert hasattr(already_documented_view, "_swag_documented")
    assert already_documented_view._swag_documented is True
