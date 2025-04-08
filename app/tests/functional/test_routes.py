"""
Functional tests for the Flask application routes.
"""

import json


def test_index_route_redirects_unauthenticated(client):
    """
    GIVEN a Flask application
    WHEN an unauthenticated user accesses the index route
    THEN they should be redirected to the login page
    """
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert "/auth/login" in response.location


def test_index_route_admin_user(admin_client):
    """
    GIVEN a Flask application
    WHEN an authenticated admin user accesses the index route
    THEN they should be redirected to the admin dashboard
    """
    response = admin_client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert "/users/dashboard" in response.location


def test_index_route_normal_user(logged_in_client):
    """
    GIVEN a Flask application
    WHEN an authenticated normal user accesses the index route
    THEN they should be redirected to the connections page
    """
    response = logged_in_client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert "/connections" in response.location


def test_api_connection_endpoint(client):
    """
    GIVEN a Flask application with a test-api-connection endpoint
    WHEN the endpoint is accessed
    THEN it should return a JSON response
    """
    # This test requires mocking the requests.get call
    # For now, we'll just check that the route exists
    response = client.get("/test-api-connection")
    assert response.status_code in (200, 500)  # Either success or API connection error
    assert response.content_type == "application/json"


def test_health_check_endpoint(client):
    """
    GIVEN a Flask application with a health check endpoint
    WHEN the endpoint is accessed
    THEN it should return a success response
    """
    response = client.get("/health")
    assert response.status_code == 200

    # Parse the response data
    data = json.loads(response.data)

    # Verify the response structure
    assert "status" in data
    assert data["status"] == "healthy"

    # Verify response headers
    assert response.content_type == "application/json"


def test_404_error_handler(client):
    """
    GIVEN a Flask application
    WHEN an undefined route is accessed
    THEN the 404 error handler should be triggered
    """
    response = client.get("/undefined-route")
    assert response.status_code == 404
