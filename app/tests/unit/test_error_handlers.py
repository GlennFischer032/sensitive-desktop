"""
This module contains unit tests for error handlers in the Flask application.
"""
import pytest
from flask import Flask, abort


def test_error_handlers_registered(app):
    """
    GIVEN a Flask application
    WHEN the application is initialized
    THEN check that all required error handlers are registered
    """
    # Verify the error handlers are registered in the app
    assert 404 in app.error_handler_spec[None]
    assert 500 in app.error_handler_spec[None]
    assert 403 in app.error_handler_spec[None]
    assert 429 in app.error_handler_spec[None]


def test_404_error_handler(app):
    """
    GIVEN a Flask application
    WHEN a 404 error is triggered
    THEN check that the error handler returns the correct response
    """
    client = app.test_client()

    # Request a non-existent URL to trigger a 404
    response = client.get("/nonexistent-path")

    # Check response code
    assert response.status_code == 404

    # Check that the response contains information about the error
    assert b"Not Found" in response.data
