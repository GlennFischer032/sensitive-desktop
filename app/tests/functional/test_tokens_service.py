"""
Functional tests for the tokens service.
"""

from unittest.mock import patch, MagicMock
import json
from urllib.parse import quote


def test_view_tokens_page_as_admin(admin_client):
    """
    GIVEN a Flask application with a logged-in admin
    WHEN the tokens page is requested
    THEN check the response is valid
    """
    # Mock the tokens client to return test data
    with patch("app.clients.factory.client_factory.get_tokens_client") as mock_get_client:
        # Set up the mock client
        mock_client = MagicMock()
        mock_client.list_tokens.return_value = {
            "tokens": [
                {
                    "id": "token1",
                    "name": "Test Token 1",
                    "created_at": "2023-01-01T12:00:00Z",
                    "expires_at": "2024-01-01T12:00:00Z",
                    "last_used": "2023-06-01T15:30:00Z",
                    "revoked_at": None,
                    "created_by": "admin",
                },
                {
                    "id": "token2",
                    "name": "Test Token 2",
                    "created_at": "2023-02-01T12:00:00Z",
                    "expires_at": "2024-02-01T12:00:00Z",
                    "last_used": None,
                    "revoked_at": "2023-03-01T12:00:00Z",
                    "created_by": "admin",
                },
            ]
        }
        mock_get_client.return_value = mock_client

        # Make the request to the tokens page
        response = admin_client.get("/tokens/", follow_redirects=True)

        # Verify the response
        assert response.status_code == 200
        assert b"API Tokens" in response.data
        assert b"Test Token 1" in response.data
        assert b"Test Token 2" in response.data


def test_view_tokens_page_as_regular_user(logged_in_client):
    """
    GIVEN a Flask application with a logged-in regular user
    WHEN the tokens page is requested
    THEN check the user is blocked from accessing it
    """
    response = logged_in_client.get("/tokens/", follow_redirects=True)

    # Should be redirected with an error message
    assert response.status_code == 200
    assert b"You need administrator privileges" in response.data


def test_view_tokens_page_unauthenticated(client):
    """
    GIVEN a Flask application with no logged-in user
    WHEN the tokens page is requested
    THEN check the user is redirected to the login page
    """
    response = client.get("/tokens/", follow_redirects=False)

    # Verify redirect to login page
    assert response.status_code == 302
    assert "/auth/login" in response.location


def test_view_tokens_api_error(admin_client):
    """
    GIVEN a Flask application with a logged-in admin
    WHEN the tokens page is requested but an API error occurs
    THEN check an error message is displayed
    """
    # Mock the tokens client to raise an exception
    with patch("app.clients.factory.client_factory.get_tokens_client") as mock_get_client:
        # Set up the mock client to raise an exception
        mock_client = MagicMock()
        mock_client.list_tokens.side_effect = Exception("Failed to fetch tokens")
        mock_get_client.return_value = mock_client

        # Make the request to the tokens page
        response = admin_client.get("/tokens/", follow_redirects=True)

        # Verify the response
        assert response.status_code == 200
        assert b"Error retrieving API tokens" in response.data


def test_view_tokens_with_new_token_param(admin_client):
    """
    GIVEN a Flask application with a logged-in admin
    WHEN the tokens page is requested with a new_token parameter
    THEN check the new token is displayed
    """
    # Mock the tokens client to return test data
    with patch("app.clients.factory.client_factory.get_tokens_client") as mock_get_client:
        # Set up the mock client
        mock_client = MagicMock()
        mock_client.list_tokens.return_value = {"tokens": []}
        mock_get_client.return_value = mock_client

        # Create a new token data and URL encode it
        new_token = {
            "id": "new-token",
            "name": "New API Token",
            "token": "test-token-value",
            "expires_at": "2024-12-31T23:59:59Z",
        }
        encoded_token = quote(json.dumps(new_token))

        # Make the request to the tokens page with new_token parameter
        response = admin_client.get(f"/tokens/?new_token={encoded_token}", follow_redirects=True)

        # Verify the response
        assert response.status_code == 200
        assert b"New API Token" in response.data
        assert b"test-token-value" in response.data


def test_parse_date_safely():
    """
    GIVEN various date string formats
    WHEN the parse_date_safely function is called
    THEN check it correctly parses the dates
    """
    from app.services.tokens.routes import parse_date_safely

    # Test with valid ISO format
    dt = parse_date_safely("2023-01-01T12:00:00Z")
    assert dt.year == 2023
    assert dt.month == 1
    assert dt.day == 1
    assert dt.hour == 12

    # Test with None
    assert parse_date_safely(None) is None

    # Test with invalid format
    assert parse_date_safely("not-a-date") is None
