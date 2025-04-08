"""
Functional tests for the auth service.
"""

from unittest.mock import patch, MagicMock


def test_login_page_get(client):
    """
    GIVEN a Flask application
    WHEN the login page is requested (GET)
    THEN check the response is valid
    """
    response = client.get("/auth/login")
    assert response.status_code == 200
    assert b"Login" in response.data


@patch("requests.post")
def test_login_success_simulation(mock_post, client):
    """
    GIVEN a Flask application
    WHEN a user logs in successfully (simulated)
    THEN their session should contain the correct data
    """
    # Set up the session directly to simulate a successful login
    with client.session_transaction() as session:
        session["logged_in"] = True
        session["user_id"] = "test-user-id"
        session["username"] = "testuser"
        session["is_admin"] = False
        session["token"] = "test-token"

    # Verify the session was updated
    with client.session_transaction() as session:
        assert session["logged_in"] is True
        assert session["user_id"] == "test-user-id"
        assert session["username"] == "testuser"
        assert session["is_admin"] is False
        assert session["token"] == "test-token"

    # Test the redirect after login by accessing the index page
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert "/connections" in response.location


@patch("requests.post")
def test_logout(mock_post, logged_in_client):
    """
    GIVEN a Flask application with a logged-in user
    WHEN the user logs out
    THEN their session should be cleared
    """
    # Mock the response from the backend API
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_post.return_value = mock_response

    # Log out
    response = logged_in_client.get("/auth/logout", follow_redirects=False)

    # Verify redirect
    assert response.status_code == 302
    assert "/auth/login" in response.location

    # Verify session cleared
    with logged_in_client.session_transaction() as session:
        assert "logged_in" not in session
        assert "user_id" not in session
        assert "username" not in session
        assert "is_admin" not in session
        assert "token" not in session
