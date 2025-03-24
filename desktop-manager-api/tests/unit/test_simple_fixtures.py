"""Simplified fixtures for testing routes."""

import pytest
from flask import Flask, g, jsonify, request
from http import HTTPStatus

from desktop_manager.core.exceptions import ValidationError, APIError

@pytest.fixture
def app_with_mocks(mocker):
    """Create a Flask app with mocked services."""
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["DEBUG"] = True

    # Setup mock database client that will be available via Flask g object
    mock_db_client = mocker.MagicMock()
    app.mock_db_client = mock_db_client

    @app.before_request
    def before_request():
        g.db_client = app.mock_db_client

    # Register test routes
    @app.route("/test_create_user", methods=["POST"])
    def test_create_user():
        """Test route for user creation."""
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), HTTPStatus.BAD_REQUEST

        username = request.json.get("username")

        # Test for validation error - missing username
        if not username:
            # Using the correct ValidationError constructor
            raise ValidationError("Username is required")

        # Test for custom validation error
        if username == "baduser":
            # Using the correct ValidationError constructor
            raise ValidationError("Username 'baduser' is not allowed")

        # Create user with mock database
        try:
            g.db_client.execute_query("INSERT INTO users...", (username,))
            return jsonify({"message": "User created successfully"}), HTTPStatus.CREATED
        except APIError as e:
            # Re-raise any API errors
            raise e

    @app.route("/test_check_user", methods=["GET"])
    def test_check_user():
        """Test route for checking user existence."""
        username = request.args.get("username")

        # Test for missing username
        if not username:
            raise ValidationError("Username is required")

        # Check if user exists
        try:
            # Simulate database query
            result = g.db_client.execute_query("SELECT * FROM users WHERE username = %s", (username,))
            return jsonify({"exists": bool(result)}), HTTPStatus.OK
        except APIError as e:
            # Re-raise any API errors
            raise e

    # Add error handlers
    @app.errorhandler(ValidationError)
    def handle_validation_error(error):
        return jsonify(error.to_dict()), error.status_code

    @app.errorhandler(APIError)
    def handle_api_error(error):
        return jsonify(error.to_dict()), error.status_code

    return app

@pytest.fixture
def client(app_with_mocks):
    """Create a test client for the app."""
    return app_with_mocks.test_client()

@pytest.fixture
def mock_db_client(app_with_mocks):
    """Get the mock database client from the app."""
    return app_with_mocks.mock_db_client


# Test functions
def test_create_user_validation_error(client, mock_db_client):
    """Test user creation with validation error."""
    # Make request with validation error (missing username)
    response = client.post(
        "/test_create_user",
        json={"email": "test@example.com"},
        content_type="application/json"
    )

    # Should be BAD_REQUEST
    assert response.status_code == HTTPStatus.BAD_REQUEST
    data = response.get_json()
    assert "message" in data
    assert "Username is required" in data["message"]


def test_create_user_custom_validation_error(client, mock_db_client):
    """Test user creation with custom validation error."""
    # Make request with baduser username
    response = client.post(
        "/test_create_user",
        json={"username": "baduser", "email": "test@example.com"},
        content_type="application/json"
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
        content_type="application/json"
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
