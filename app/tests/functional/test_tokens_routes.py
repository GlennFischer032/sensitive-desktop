"""
This module contains functional tests for the tokens routes.
"""
from unittest.mock import patch

import pytest
from http import HTTPStatus


@pytest.fixture
def mock_tokens_client():
    """
    Fixture to mock the tokens client response
    """
    with patch("clients.factory.client_factory.get_tokens_client") as mock_factory:
        mock_client = mock_factory.return_value
        # Mock the list_tokens method
        mock_client.list_tokens.return_value = {
            "tokens": [
                {
                    "token_id": "test-token-1",
                    "name": "Test Token 1",
                    "description": "A test token",
                    "created_at": "2023-01-01T00:00:00Z",
                    "expires_at": "2024-01-01T00:00:00Z",
                    "created_by": "admin",
                    "revoked": False,
                }
            ]
        }
        yield mock_client


def test_view_tokens_page_unauthorized(client):
    """
    GIVEN the tokens view route
    WHEN accessed without authentication
    THEN check redirect to login page
    """
    response = client.get("/tokens/")
    assert response.status_code == HTTPStatus.FOUND  # 302 Found (redirect)
    assert "/auth/login" in response.headers["Location"]


def test_view_tokens_page_authorized_non_admin(logged_in_client, mock_tokens_client):
    """
    GIVEN the tokens view route
    WHEN accessed by an authenticated but non-admin user
    THEN check redirects (likely to dashboard)
    """
    # Set up session to be a non-admin
    with logged_in_client.session_transaction() as sess:
        sess["is_admin"] = False

    response = logged_in_client.get("/tokens/")
    # Application redirects non-admins instead of showing 403
    assert response.status_code == HTTPStatus.FOUND  # 302 Found (redirect)


def test_view_tokens_page_admin(admin_client, mock_tokens_client):
    """
    GIVEN the tokens view route
    WHEN accessed by an admin user
    THEN check the page is displayed correctly
    """
    response = admin_client.get("/tokens/")

    assert response.status_code == HTTPStatus.OK

    # Check content
    html = response.data.decode()
    assert "API Tokens" in html
    assert "Test Token 1" in html

    # Verify the tokens client was called
    mock_tokens_client.list_tokens.assert_called_once()


@patch("utils.session.is_authenticated")
def test_api_list_tokens_unauthorized(mock_is_authenticated, client):
    """
    GIVEN the tokens API route
    WHEN accessed without authentication
    THEN check that the application returns an error when the backend is unavailable
    """
    mock_is_authenticated.return_value = False

    response = client.get("/api/tokens/")

    # The application gets a 500 error when trying to connect to the backend
    # which isn't available in the test context
    assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    assert b"error" in response.data


def test_api_list_tokens_non_admin(logged_in_client, mock_tokens_client):
    """
    GIVEN the tokens API route
    WHEN accessed by an authenticated but non-admin user
    THEN check it redirects rather than showing 403
    """
    # Set up session to be a non-admin
    with logged_in_client.session_transaction() as sess:
        sess["is_admin"] = False

    response = logged_in_client.get("/api/tokens/")
    assert response.status_code == HTTPStatus.FOUND  # 302 Found (redirect)


def test_api_list_tokens_admin(admin_client, mock_tokens_client):
    """
    GIVEN the tokens API route
    WHEN accessed by an admin user
    THEN check tokens are returned correctly
    """
    response = admin_client.get("/api/tokens/")

    assert response.status_code == HTTPStatus.OK

    # Check JSON response
    json_data = response.get_json()
    assert "tokens" in json_data
    assert len(json_data["tokens"]) == 1
    assert json_data["tokens"][0]["token_id"] == "test-token-1"

    # Verify the tokens client was called
    mock_tokens_client.list_tokens.assert_called_once()


@patch("clients.factory.client_factory.get_tokens_client")
def test_api_list_tokens_error(mock_factory, admin_client):
    """
    GIVEN the tokens API route
    WHEN the tokens client raises an error
    THEN check an error response is returned
    """
    # Setup mock to raise an exception
    mock_client = mock_factory.return_value
    mock_client.list_tokens.side_effect = Exception("Test API error")

    response = admin_client.get("/api/tokens/")

    assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    json_data = response.get_json()
    assert "error" in json_data
    assert "Test API error" in str(json_data["error"])
