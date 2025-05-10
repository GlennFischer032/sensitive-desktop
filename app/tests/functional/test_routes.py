"""
This module contains functional tests for the application routes.
"""
import json
from unittest.mock import patch, MagicMock
from http import HTTPStatus


def test_health_check(client):
    """
    GIVEN a Flask application
    WHEN the health check endpoint is accessed
    THEN check the correct response is returned
    """
    response = client.get("/health")
    assert response.status_code == HTTPStatus.OK
    assert json.loads(response.data) == {"status": "healthy"}


def test_api_connection_route(client):
    """
    GIVEN a Flask application
    WHEN the API connection test endpoint is accessed
    THEN check the API status is returned
    """
    # Mock the requests.get method
    with patch("requests.get") as mock_get:
        # Configure the mock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"status": "healthy"}'
        mock_get.return_value = mock_response

        # Access the endpoint
        response = client.get("/test-api-connection")

        # Verify the response
        assert response.status_code == HTTPStatus.OK
        data = json.loads(response.data)
        assert "api_url" in data
        assert "status_code" in data
        assert data["status_code"] == 200
        assert "response" in data
        assert data["response"] == '{"status": "healthy"}'


def test_api_connection_error(client):
    """
    GIVEN a Flask application
    WHEN the API connection test endpoint is accessed but the API is down
    THEN check an appropriate error response is returned
    """
    # Mock the requests.get method to raise an exception
    with patch("requests.get") as mock_get:
        # Configure the mock to raise an exception
        mock_get.side_effect = Exception("Connection refused")

        # Access the endpoint
        response = client.get("/test-api-connection")

        # Verify the response
        assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
        data = json.loads(response.data)
        assert "error" in data
        assert "Connection refused" in data["error"]
        assert "api_url" in data


def test_redirect_when_not_logged_in(client):
    """
    GIVEN a Flask application with an unauthenticated client
    WHEN the root endpoint is accessed
    THEN check the user is redirected to the login page
    """
    response = client.get("/", follow_redirects=False)
    assert response.status_code == HTTPStatus.FOUND  # 302 redirect
    assert "/auth/login" in response.location


def test_redirect_regular_user(logged_in_client):
    """
    GIVEN a Flask application with an authenticated regular user
    WHEN the root endpoint is accessed
    THEN check the user is redirected to the connections page
    """
    # The logged_in_client fixture is already configured with a non-admin user
    # Test with regular user
    response = logged_in_client.get("/", follow_redirects=False)
    assert response.status_code == HTTPStatus.FOUND
    assert "/dashboard" not in response.location  # Shouldn't redirect to admin dashboard


def test_redirect_admin_user(admin_client):
    """
    GIVEN a Flask application with an authenticated admin user
    WHEN the root endpoint is accessed
    THEN check the user is redirected to the admin dashboard
    """
    # The admin_client fixture is already configured with an admin user
    response = admin_client.get("/", follow_redirects=False)
    assert response.status_code == HTTPStatus.FOUND
    assert "/dashboard" in response.location or "/users/dashboard" in response.location


def test_app_routes_coverage(client):
    """
    A comprehensive test to ensure code coverage of the main application routes.
    """
    # Test health check endpoint
    response = client.get("/health")
    assert response.status_code == HTTPStatus.OK
    assert json.loads(response.data) == {"status": "healthy"}

    # Test API connection endpoint
    with patch("requests.get") as mock_get:
        # Configure the mock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"status": "healthy"}'
        mock_get.return_value = mock_response

        response = client.get("/test-api-connection")
        assert response.status_code == HTTPStatus.OK

    # Test 404 error handler
    response = client.get("/nonexistent-endpoint")
    assert response.status_code == HTTPStatus.NOT_FOUND
    assert b"Page Not Found" in response.data
