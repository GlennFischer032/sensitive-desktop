"""Unit tests for authentication routes."""

import json
from datetime import datetime, timedelta
from unittest.mock import patch

import jwt
import pytest
from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash

from desktop_manager.api.models.user import User
from desktop_manager.api.routes.auth_routes import auth_bp


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
        password_hash=generate_password_hash("password123"),
        email="test@example.com",
        organization="Test Org",
        is_admin=False,
    )
    test_db.add(user)
    test_db.commit()
    return user


@pytest.fixture()
def test_admin(test_db):
    """Create a test admin user in the database."""
    admin = User(
        username="admin",
        password_hash=generate_password_hash("adminpass"),
        email="admin@example.com",
        organization="Admin Org",
        is_admin=True,
    )
    test_db.add(admin)
    test_db.commit()
    return admin


@pytest.fixture()
def mock_guacamole():
    """Mock the Guacamole client and its methods."""
    with patch(
        "desktop_manager.api.routes.auth_routes.guacamole_login"
    ) as mock_login, patch(
        "desktop_manager.api.routes.auth_routes.create_guacamole_user"
    ) as mock_create, patch(
        "desktop_manager.api.routes.auth_routes.ensure_all_users_group"
    ) as mock_ensure_all, patch(
        "desktop_manager.api.routes.auth_routes.ensure_admins_group"
    ) as mock_ensure_admins, patch(
        "desktop_manager.api.routes.auth_routes.add_user_to_group"
    ) as mock_add_to_group, patch(
        "desktop_manager.api.routes.auth_routes.delete_guacamole_user"
    ) as mock_delete:
        mock_login.return_value = "mock_token"
        yield {
            "login": mock_login,
            "create": mock_create,
            "ensure_all": mock_ensure_all,
            "ensure_admins": mock_ensure_admins,
            "add_to_group": mock_add_to_group,
            "delete": mock_delete,
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

    # Mock get_db to use test database
    def mock_get_db():
        yield test_db

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
                    db_session = next(mock_get_db())
                    current_user = (
                        db_session.query(User).filter(User.id == data["user_id"]).first()
                    )

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

    # Mock the decorators and get_db
    with patch("desktop_manager.api.routes.auth_routes.get_db", mock_get_db), patch(
        "desktop_manager.api.routes.auth_routes.token_required", test_token_required
    ), patch(
        "desktop_manager.api.routes.auth_routes.admin_required", test_admin_required
    ):
        # Import the blueprint after patching the decorators
        app.register_blueprint(auth_bp, url_prefix="/auth")

        yield app


@pytest.fixture()
def client(test_app):
    """Create a test client."""
    return test_app.test_client()


# Login tests
def test_login_success(client, test_user):
    """Test successful login."""
    response = client.post(
        "/auth/login", json={"username": "testuser", "password": "password123"}
    )
    data = json.loads(response.data)
    assert response.status_code == 200
    assert "token" in data
    assert data["username"] == "testuser"
    assert data["is_admin"] is False


def test_login_missing_json(client):
    """Test login with missing JSON."""
    response = client.post("/auth/login")
    assert response.status_code == 400
    assert b"Missing JSON in request" in response.data


def test_login_empty_json(client):
    """Test login with empty JSON."""
    response = client.post("/auth/login", json={})
    assert response.status_code == 400
    assert b"Missing JSON data" in response.data


def test_login_missing_fields(client):
    """Test login with missing fields."""
    response = client.post("/auth/login", json={"username": "testuser"})
    assert response.status_code == 400
    assert b"Missing username or password" in response.data


def test_login_invalid_credentials(client, test_user):
    """Test login with invalid credentials."""
    response = client.post(
        "/auth/login", json={"username": "testuser", "password": "wrongpassword"}
    )
    assert response.status_code == 401
    assert b"Invalid credentials" in response.data


# Registration tests
def test_register_success(client, test_admin, mock_guacamole, admin_token):
    """Test successful user registration by admin."""
    response = client.post(
        "/auth/register",
        json={
            "username": "newuser",
            "password": "newpassword",
            "email": "new@example.com",
            "organization": "New Org",
            "is_admin": False,
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    data = json.loads(response.data)
    assert response.status_code == 201
    assert "registered successfully" in data["message"]


def test_register_as_admin(client, test_admin, mock_guacamole, admin_token):
    """Test registering a new admin user."""
    response = client.post(
        "/auth/register",
        json={
            "username": "newadmin",
            "password": "adminpass",
            "email": "newadmin@example.com",
            "organization": "Admin Org",
            "is_admin": True,
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    data = json.loads(response.data)
    assert response.status_code == 201
    assert "registered successfully" in data["message"]
    mock_guacamole["ensure_admins"].assert_called_once()
    mock_guacamole["add_to_group"].assert_called_once_with(
        "mock_token", "newadmin", "admins"
    )


def test_register_non_admin(client, user_token):
    """Test registration attempt by non-admin user."""
    response = client.post(
        "/auth/register",
        json={
            "username": "newuser2",
            "password": "password123",
            "email": "new2@example.com",
            "organization": "New Org",
        },
        headers={"Authorization": f"Bearer {user_token}"},
    )

    # Non-admin should not be able to register users
    assert response.status_code == 403
    assert b"Admin privilege required" in response.data


def test_register_missing_token(client):
    """Test registration with missing token."""
    response = client.post(
        "/auth/register",
        json={
            "username": "newuser",
            "password": "newpassword",
            "email": "new@example.com",
        },
    )
    assert response.status_code == 401
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
    assert b"Token validation failed" in response.data


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
    assert response.status_code == 400
    assert b"Username, password, and email are required" in response.data


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
    assert response.status_code == 400
    assert b"Username already exists" in response.data


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
    assert response.status_code == 500
    assert b"Failed to authenticate with Guacamole API" in response.data


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
    assert response.status_code == 500
    assert b"Failed to create user in Guacamole" in response.data


def test_register_guacamole_group_error(client, admin_token, mock_guacamole):
    """Test registration with Guacamole group assignment error."""
    mock_guacamole["add_to_group"].side_effect = Exception(
        "Guacamole group assignment failed"
    )

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
    assert response.status_code == 500
    assert b"Failed to assign user to group in Guacamole" in response.data
