"""Swagger documentation utilities.

This module provides helper functions for documenting routes with Swagger.
"""
from functools import wraps
from inspect import getdoc


def swag_from_doc(func):
    """Extract Swagger documentation from the function docstring.

    This decorator ensures that any function with a properly formatted
    docstring with Swagger YAML will be correctly documented in the
    OpenAPI specification. No additional decorator is needed.

    Args:
        func: The function to document

    Returns:
        The decorated function
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    # We don't need to do anything here since Flasgger automatically
    # picks up docstrings in the format we're using. This decorator
    # is just for consistency and future extensibility.
    return wrapper


def auto_document_blueprint(blueprint, _):
    """Automatically document all routes in a blueprint using their docstrings.

    This function iterates through all routes in a blueprint and applies the
    swag_from_doc decorator to them if they have docstrings.

    Args:
        blueprint: The Flask blueprint to document
        default_tag: A default tag to apply to routes without tags
    """
    for _endpoint, view_func in blueprint.view_functions.items():
        doc = getdoc(view_func)
        if doc and "---" in doc and not hasattr(view_func, "_swag_documented"):
            # If there's a docstring with a Swagger section
            view_func._swag_documented = True
            # We don't need to modify the function since Flasgger will pick up
            # the docstrings automatically. This is just for marking and future use.
