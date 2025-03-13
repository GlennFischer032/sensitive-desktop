"""Basic smoke tests for the frontend application."""

from flask import Flask
from flask.testing import FlaskClient


def test_app_creation(app: Flask) -> None:
    """Test that the application is created successfully."""
    assert app is not None
    assert app.config["TESTING"] is True


def test_health_check(client: FlaskClient) -> None:
    """Test the health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json == {"status": "healthy"}
