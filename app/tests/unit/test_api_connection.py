"""
This module contains unit tests for the API connection test endpoint.
"""
import pytest
import requests
from unittest.mock import patch, MagicMock


def test_api_connection_success(app):
    """
    GIVEN a Flask application
    WHEN the test API connection endpoint is called and the API is reachable
    THEN check that it returns a successful response
    """
    with patch("requests.get") as mock_get:
        # Mock the response from the backend API
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"status": "healthy"}'
        mock_get.return_value = mock_response

        # Make a request to the test endpoint
        client = app.test_client()
        response = client.get("/test-api-connection")

        # Check that the response is successful
        assert response.status_code == 200
        data = response.get_json()

        # Check the structure of the response
        assert "api_url" in data
        assert "status_code" in data
        assert "response" in data

        # Check the values
        assert data["status_code"] == 200
        assert data["response"] == '{"status": "healthy"}'


def test_api_connection_error(app):
    """
    GIVEN a Flask application
    WHEN the test API connection endpoint is called and the API is unreachable
    THEN check that it returns an error response
    """
    with patch("requests.get") as mock_get:
        # Mock a connection error
        mock_get.side_effect = Exception("Connection refused")

        # Make a request to the test endpoint
        client = app.test_client()
        response = client.get("/test-api-connection")

        # Check that the response is an error
        assert response.status_code == 500
        data = response.get_json()

        # Check the structure of the response
        assert "error" in data
        assert "api_url" in data

        # Check the values
        assert "Connection refused" in data["error"]


def test_api_connection_timeout(app):
    """
    GIVEN a Flask application
    WHEN the test API connection endpoint is called and the API times out
    THEN check that it returns an error response
    """
    with patch("requests.get") as mock_get:
        # Mock a timeout error
        mock_get.side_effect = requests.exceptions.Timeout("Request timed out")

        # Make a request to the test endpoint
        client = app.test_client()
        response = client.get("/test-api-connection")

        # Check that the response is an error
        assert response.status_code == 500
        data = response.get_json()

        # Check the structure of the response
        assert "error" in data
        assert "api_url" in data

        # Check the values
        assert "Request timed out" in data["error"]
