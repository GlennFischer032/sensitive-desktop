"""Simplified unit tests for user routes."""

from http import HTTPStatus

from desktop_manager.core.exceptions import APIError


# Import fixtures from test_simple_fixtures


def test_create_user_validation_error(client, mock_db_client):
    """Test user creation with validation error."""
    # Make request with validation error (missing username)
    response = client.post("/test_create_user", json={"email": "test@example.com"}, content_type="application/json")

    # Should be BAD_REQUEST
    assert response.status_code == HTTPStatus.BAD_REQUEST
    data = response.get_json()
    assert "message" in data
    assert "Username is required" in data["message"]


def test_create_user_with_custom_validation_error(client, mock_db_client):
    """Test user creation with custom validation error."""
    # Make request with baduser username
    response = client.post(
        "/test_create_user",
        json={"username": "baduser", "email": "test@example.com"},
        content_type="application/json",
    )

    # Should be BAD_REQUEST
    assert response.status_code == HTTPStatus.BAD_REQUEST
    data = response.get_json()
    assert "message" in data
    assert "not allowed" in data["message"]


def test_create_user_database_error(client, mock_db_client):
    """Test user creation with database error."""
    # Configure mock to raise database error
    mock_db_client.execute_query.side_effect = APIError("Database error", HTTPStatus.INTERNAL_SERVER_ERROR)

    # Make request
    response = client.post(
        "/test_create_user",
        json={"username": "testuser", "email": "test@example.com"},
        content_type="application/json",
    )

    # Should be INTERNAL_SERVER_ERROR
    assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    data = response.get_json()
    assert "message" in data
    assert "Database error" in data["message"]


def test_check_user_without_parameters(client):
    """Test checking user existence without parameters."""
    # Make request without username parameter
    response = client.get("/test_check_user")

    # Should be BAD_REQUEST
    assert response.status_code == HTTPStatus.BAD_REQUEST
    data = response.get_json()
    assert "message" in data
    assert "Username is required" in data["message"]


def test_check_user_database_error(client, mock_db_client):
    """Test checking user existence with database error."""
    # Configure mock to raise database error
    mock_db_client.execute_query.side_effect = APIError("Database error", HTTPStatus.INTERNAL_SERVER_ERROR)

    # Make request with username parameter
    response = client.get("/test_check_user?username=testuser")

    # Should be INTERNAL_SERVER_ERROR
    assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    data = response.get_json()
    assert "message" in data
    assert "Database error" in data["message"]


def test_check_user_exists(client, mock_db_client):
    """Test checking existence of a user that exists."""
    # Configure mock to return a user
    mock_db_client.execute_query.return_value = [{"username": "testuser"}]

    # Make request with username parameter
    response = client.get("/test_check_user?username=testuser")

    # Should be OK and user exists
    assert response.status_code == HTTPStatus.OK
    data = response.get_json()
    assert "exists" in data
    assert data["exists"] is True


def test_check_user_not_exists(client, mock_db_client):
    """Test checking existence of a user that does not exist."""
    # Configure mock to return no users
    mock_db_client.execute_query.return_value = []

    # Make request with username parameter
    response = client.get("/test_check_user?username=testuser")

    # Should be OK and user does not exist
    assert response.status_code == HTTPStatus.OK
    data = response.get_json()
    assert "exists" in data
    assert data["exists"] is False
