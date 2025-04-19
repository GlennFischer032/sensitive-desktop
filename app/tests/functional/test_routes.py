"""
This module contains functional tests for the application routes.
"""


def test_health_check(client):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/health' endpoint is requested (GET)
    THEN check that the response is valid and returns a 200 status code
    """
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json["status"] == "healthy"


def test_api_connection_route(client):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/test-api-connection' endpoint is requested (GET)
    THEN check that the response contains expected keys
    """
    response = client.get("/test-api-connection")
    # Since we can't guarantee a successful connection in tests,
    # we'll just check that the endpoint responds with expected keys
    assert "api_url" in response.json
    assert response.json["api_url"] == "http://localhost:5000"


def test_redirect_when_not_logged_in(client):
    """
    GIVEN a Flask application configured for testing
    WHEN the root URL '/' is requested (GET) without being logged in
    THEN check the user is redirected to the login page
    """
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302  # Redirect status code
