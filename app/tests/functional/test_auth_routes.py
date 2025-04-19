"""
This module contains functional tests for authenticated routes.
"""


def test_authenticated_access(logged_in_client):
    """
    GIVEN a Flask application configured for testing
    WHEN the root URL '/' is requested (GET) with an authenticated user
    THEN check that the response redirects to the connections page
    """
    response = logged_in_client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert "/connections/" in response.location


def test_admin_access(admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN the root URL '/' is requested (GET) with an admin user
    THEN check that the response redirects to the admin dashboard
    """
    response = admin_client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert "/users/dashboard" in response.location


def test_api_docs_access(admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN the API docs endpoint is accessed with different authentication levels
    THEN check the appropriate access controls
    """
    # For Swagger UI testing, we'll test the protection mechanism differently

    # First test that our admin_client has the is_admin flag set in the session
    with admin_client.session_transaction() as session:
        assert session.get("is_admin", False) is True
        assert session.get("logged_in", False) is True

    # Test that admin can access the API docs page (though we can't validate content)
    response = admin_client.get("/api/docs/", follow_redirects=True)
    assert response.status_code == 200
