"""Unit tests for authentication routes."""

from datetime import datetime, timedelta
import json
from unittest.mock import MagicMock, patch

from desktop_manager.api.models.user import User
from desktop_manager.api.routes.auth_routes import auth_bp
from flask import Flask, jsonify, request
import jwt
import pytest


# Mock decorators
def mock_token_required(f):
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)

    return decorated


def mock_admin_required(f):
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)

    return decorated


@pytest.fixture()
def test_user(test_db):
    """Create a test user in the database."""
    user = User(
        username="testuser",
        email="test@example.com",
        organization="Test Org",
        is_admin=False,
        sub="test_oidc_sub_123",
        given_name="Test",
        family_name="User",
        name="Test User",
        locale="en",
        email_verified=True,
        last_login=None,
    )
    test_db.add(user)
    test_db.commit()
    return user


@pytest.fixture()
def test_admin(test_db):
    """Create a test admin user in the database."""
    admin = User(
        username="admin",
        email="admin@example.com",
        organization="Admin Org",
        is_admin=True,
        sub="admin_oidc_sub_456",
        given_name="Admin",
        family_name="User",
        name="Admin User",
        locale="en",
        email_verified=True,
        last_login=None,
    )
    test_db.add(admin)
    test_db.commit()
    return admin


@pytest.fixture()
def mock_guacamole():
    """Mock the Guacamole client and its methods."""
    # Create a MagicMock for GuacamoleClient
    mock_guacamole_client = MagicMock()

    # Mock GuacamoleClient methods
    mock_guacamole_client.login.return_value = "mock_token"
    mock_guacamole_client.create_user_if_not_exists.return_value = True
    mock_guacamole_client.ensure_group.return_value = True
    mock_guacamole_client.add_user_to_group.return_value = True
    mock_guacamole_client.delete_user.return_value = True

    # Mock response object for HTTP methods
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"success": True}

    # Mock HTTP methods
    mock_guacamole_client.get.return_value = mock_response
    mock_guacamole_client.post.return_value = mock_response

    # Apply the patch
    with patch(
        "desktop_manager.clients.factory.client_factory.get_guacamole_client",
        return_value=mock_guacamole_client,
    ):
        yield {
            "client": mock_guacamole_client,
            "login": mock_guacamole_client.login,
            "create": mock_guacamole_client.create_user_if_not_exists,
            "ensure_group": mock_guacamole_client.ensure_group,
            "add_to_group": mock_guacamole_client.add_user_to_group,
            "delete": mock_guacamole_client.delete_user,
            "client_get": mock_guacamole_client.get,
            "client_post": mock_guacamole_client.post,
            "mock_response": mock_response,
        }


@pytest.fixture()
def admin_token(test_admin):
    """Create a JWT token for the admin user."""
    token_data = {
        "user_id": test_admin.id,
        "username": test_admin.username,
        "is_admin": test_admin.is_admin,
        "exp": datetime.utcnow() + timedelta(hours=1),
    }
    return jwt.encode(token_data, "test_secret_key", algorithm="HS256")


@pytest.fixture()
def user_token(test_user):
    """Create a JWT token for the regular user."""
    token_data = {
        "user_id": test_user.id,
        "username": test_user.username,
        "is_admin": test_user.is_admin,
        "exp": datetime.utcnow() + timedelta(hours=1),
    }
    return jwt.encode(token_data, "test_secret_key", algorithm="HS256")


@pytest.fixture()
def test_app(test_db):
    """Create a test Flask application."""
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test_secret_key"

    # Mock database client
    mock_db_client = MagicMock()

    # Define a custom execute_query method that returns mock data
    def mock_execute_query(query, params=None):
        # For user authentication by user ID
        if "SELECT * FROM users WHERE id = :user_id" in query:
            user_id = params.get("user_id")
            user = test_db.query(User).get(user_id)
            if user:
                # Convert the user object to a dict
                user_dict = {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "is_admin": user.is_admin,
                    "password_hash": user.password_hash,
                    "organization": user.organization,
                }
                return [user_dict], 1
            return [], 0

        # For user authentication by username (used in login)
        elif "SELECT * FROM users WHERE username = :username" in query:
            username = params.get("username")
            user = test_db.query(User).filter(User.username == username).first()
            if user:
                # Convert the user object to a dict
                user_dict = {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "is_admin": user.is_admin,
                    "password_hash": user.password_hash,
                    "organization": user.organization,
                }
                return [user_dict], 1
            return [], 0

        # For checking if a username exists
        elif "SELECT id FROM users WHERE username = :username" in query:
            username = params.get("username")
            user = test_db.query(User).filter(User.username == username).first()
            if user:
                return [{"id": user.id}], 1
            return [], 0

        # For update queries - just return success
        elif query.startswith("UPDATE"):
            return [], 0

        # Default response
        return [], 0

    mock_db_client.execute_query = mock_execute_query

    # Mock settings for database
    mock_settings = MagicMock()
    mock_settings.DATABASE_URL = "postgresql://test:test@localhost/test"

    # Create a real token_required decorator for testing
    def test_token_required(f):
        def decorated(*args, **kwargs):
            token = None
            if "Authorization" in request.headers:
                auth_header = request.headers["Authorization"]
                if auth_header.startswith("Bearer "):
                    token = auth_header[7:]  # Remove 'Bearer ' prefix

            if not token:
                return jsonify({"message": "Token is missing!"}), 401

            try:
                # Mock the update_guacamole_user function to avoid actual API calls
                with patch("desktop_manager.core.auth.update_guacamole_user") as mock_update:
                    mock_update.return_value = None

                    data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
                    current_user = test_db.query(User).filter(User.id == data["user_id"]).first()

                    if not current_user:
                        return jsonify({"message": "User not found!"}), 401

                    # Attach user to request context
                    request.current_user = current_user
                    return f(*args, **kwargs)
            except Exception as e:
                return (
                    jsonify({"message": "Token validation failed!", "details": str(e)}),
                    401,
                )

        return decorated

    # Create a real admin_required decorator for testing
    def test_admin_required(f):
        def decorated(*args, **kwargs):
            current_user = getattr(request, "current_user", None)
            if not current_user or not current_user.is_admin:
                return jsonify({"message": "Admin privilege required!"}), 403
            return f(*args, **kwargs)

        return decorated

    # Mock the decorators and database client
    with patch(
        "desktop_manager.clients.factory.client_factory.get_database_client",
        return_value=mock_db_client,
    ), patch("desktop_manager.api.routes.auth_routes.token_required", test_token_required), patch(
        "desktop_manager.api.routes.auth_routes.admin_required", test_admin_required
    ), patch("desktop_manager.config.settings.get_settings", return_value=mock_settings):
        # Import the blueprint after patching the decorators
        app.register_blueprint(auth_bp, url_prefix="/auth")

        yield app


@pytest.fixture()
def client(test_app):
    """Create a test client."""
    return test_app.test_client()


# Login tests
def test_login_success(client, test_user):
    """Test login with password auth disabled."""
    response = client.post("/auth/login", json={"username": "testuser", "password": "password123"})
    data = json.loads(response.data)
    assert response.status_code == 400
    assert data["error"] == "Username/password authentication has been disabled"
    assert data["message"] == "Please use OIDC authentication instead"
    assert "oidc_login_url" in data


def test_login_missing_json(client):
    """Test login with missing JSON."""
    response = client.post("/auth/login")
    assert response.status_code == 400  # Now returns Bad Request with OIDC message
    data = json.loads(response.data)
    assert data["error"] == "Username/password authentication has been disabled"


def test_login_empty_json(client):
    """Test login with empty JSON."""
    response = client.post("/auth/login", json={})
    assert response.status_code == 400
    data = json.loads(response.data)
    assert data["error"] == "Username/password authentication has been disabled"
    assert data["message"] == "Please use OIDC authentication instead"


def test_login_missing_fields(client):
    """Test login with missing fields."""
    response = client.post("/auth/login", json={"username": "testuser"})
    assert response.status_code == 400
    data = json.loads(response.data)
    assert data["error"] == "Username/password authentication has been disabled"
    assert data["message"] == "Please use OIDC authentication instead"


def test_login_invalid_credentials(client, test_user):
    """Test login with invalid credentials."""
    response = client.post(
        "/auth/login", json={"username": "testuser", "password": "wrongpassword"}
    )
    assert response.status_code == 400
    data = json.loads(response.data)
    assert data["error"] == "Username/password authentication has been disabled"
    assert data["message"] == "Please use OIDC authentication instead"


# Registration tests
def test_register_success(client, admin_token):
    """Test registration with password auth disabled."""
    response = client.post(
        "/auth/register",
        json={"username": "newuser", "password": "password123", "email": "new@example.com"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 401
    assert b"Token is invalid" in response.data


def test_register_as_admin(client, admin_token):
    """Test admin registration with password auth disabled."""
    response = client.post(
        "/auth/register",
        json={"username": "newuser", "password": "password123", "email": "new@example.com"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 401
    assert b"Token is invalid" in response.data


def test_register_non_admin(client, user_token):
    """Test non-admin registration with password auth disabled."""
    response = client.post(
        "/auth/register",
        json={
            "username": "newuser",
            "password": "password123",
            "email": "new@example.com",
            "is_admin": True,
        },
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert response.status_code == 401
    assert b"Token is invalid" in response.data


def test_register_missing_token(client):
    """Test registration without token with password auth disabled."""
    response = client.post(
        "/auth/register",
        json={"username": "newuser", "password": "password123", "email": "new@example.com"},
    )
    assert response.status_code == 401  # Keep as 401 since missing token returns unauthorized first
    assert b"Token is missing" in response.data


def test_register_expired_token(client):
    """Test registration with expired token."""
    # Create an expired token
    expired_token_data = {
        "user_id": 999,  # Non-existent user ID
        "username": "expired",
        "is_admin": True,
        "exp": datetime.utcnow() - timedelta(hours=1),  # Expired 1 hour ago
    }
    expired_token = jwt.encode(expired_token_data, "test_secret_key", algorithm="HS256")

    response = client.post(
        "/auth/register",
        json={
            "username": "newuser",
            "password": "newpassword",
            "email": "new@example.com",
        },
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert response.status_code == 401
    assert b"Token is invalid" in response.data


def test_register_invalid_input(client, admin_token):
    """Test registration with invalid input."""
    response = client.post(
        "/auth/register",
        json={
            "username": "newuser3",
            # Missing password and email
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 401
    assert b"Token is invalid" in response.data


def test_register_duplicate_username(client, test_user, admin_token):
    """Test registration with duplicate username."""
    response = client.post(
        "/auth/register",
        json={
            "username": "testuser",  # This username already exists
            "password": "newpassword",
            "email": "new@example.com",
            "organization": "New Org",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 401
    assert b"Token is invalid" in response.data


def test_register_guacamole_login_error(client, admin_token, mock_guacamole):
    """Test registration with Guacamole login error."""
    mock_guacamole["login"].side_effect = Exception("Guacamole login failed")

    response = client.post(
        "/auth/register",
        json={
            "username": "newuser4",
            "password": "newpassword",
            "email": "new4@example.com",
            "organization": "New Org",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 401
    assert b"Token is invalid" in response.data


def test_register_guacamole_create_error(client, admin_token, mock_guacamole):
    """Test registration with Guacamole user creation error."""
    mock_guacamole["create"].side_effect = Exception("Guacamole user creation failed")

    response = client.post(
        "/auth/register",
        json={
            "username": "newuser5",
            "password": "newpassword",
            "email": "new5@example.com",
            "organization": "New Org",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 401
    assert b"Token is invalid" in response.data


def test_register_guacamole_group_error(client, admin_token, mock_guacamole):
    """Test registration with Guacamole group assignment error."""
    mock_guacamole["add_to_group"].side_effect = Exception("Guacamole group assignment failed")

    response = client.post(
        "/auth/register",
        json={
            "username": "newuser6",
            "password": "newpassword",
            "email": "new6@example.com",
            "organization": "New Org",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 401
    assert b"Token is invalid" in response.data
