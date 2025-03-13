"""Unit tests for OIDC authentication routes."""

import base64
import datetime
import hashlib
import json
import secrets
from functools import wraps
from http import HTTPStatus
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse

import pytest
import requests
from desktop_manager.api.models.user import PKCEState, SocialAuthAssociation, User
from desktop_manager.api.routes.oidc_routes import oidc_bp
from flask import Flask
from sqlalchemy import text

# Constants for testing
TEST_STATE = "test_state_123456"
TEST_CODE = "test_authorization_code"
TEST_CODE_VERIFIER = "test_code_verifier_123456"
TEST_CODE_CHALLENGE = (
    base64.urlsafe_b64encode(hashlib.sha256(TEST_CODE_VERIFIER.encode()).digest())
    .decode()
    .rstrip("=")
)


# Mock decorators
def mock_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)

    return decorated


def mock_admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)

    return decorated


@pytest.fixture(autouse=True)
def setup_database(test_db, test_engine):
    """Set up the database with the correct schema before each test."""
    # Drop and recreate the necessary tables with the current schema
    User.__table__.drop(test_engine, checkfirst=True)
    User.__table__.create(test_engine, checkfirst=True)

    # Create PKCEState table if not exists
    if not hasattr(PKCEState, "__table__"):
        pytest.skip("PKCEState table not defined")

    PKCEState.__table__.drop(test_engine, checkfirst=True)
    PKCEState.__table__.create(test_engine, checkfirst=True)

    # Create SocialAuthAssociation table if not exists
    if not hasattr(SocialAuthAssociation, "__table__"):
        pytest.skip("SocialAuthAssociation table not defined")

    SocialAuthAssociation.__table__.drop(test_engine, checkfirst=True)
    SocialAuthAssociation.__table__.create(test_engine, checkfirst=True)

    # Clean up before test
    test_db.execute(text("DELETE FROM users"))
    test_db.execute(text("DELETE FROM pkce_state"))
    test_db.execute(text("DELETE FROM social_auth_association"))
    test_db.commit()

    # Run the test
    yield

    # Clean up after test
    test_db.execute(text("DELETE FROM users"))
    test_db.execute(text("DELETE FROM pkce_state"))
    test_db.execute(text("DELETE FROM social_auth_association"))
    test_db.commit()


@pytest.fixture()
def test_app(test_db):
    """Create a test Flask application."""
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test_secret_key"
    app.config["SERVER_NAME"] = "test.local"  # Required for url_for to work

    # OIDC-specific configuration
    app.config["SOCIAL_AUTH_OIDC_PROVIDER_URL"] = "https://oidc.test"
    app.config["SOCIAL_AUTH_OIDC_CLIENT_ID"] = "test_client_id"
    app.config["SOCIAL_AUTH_OIDC_CLIENT_SECRET"] = "test_client_secret"
    app.config["SOCIAL_AUTH_LOGIN_REDIRECT_URL"] = "https://frontend.test"
    app.config[
        "SOCIAL_AUTH_VERIFICATION_CALLBACK_URL"
    ] = "https://api.test/auth/oidc/callback"

    # Mock get_db to use test database
    def mock_get_db():
        yield test_db

    with patch("desktop_manager.api.routes.oidc_routes.get_db", mock_get_db):
        # Register the blueprint
        app.register_blueprint(oidc_bp)

        # Need an application context for url_for to work
        with app.app_context():
            yield app


@pytest.fixture()
def test_client(test_app):
    """Create a test client."""
    with test_app.test_client() as client:
        yield client


@pytest.fixture()
def mock_guacamole():
    """Mock Guacamole API calls."""
    with patch(
        "desktop_manager.api.routes.oidc_routes.ensure_all_users_group"
    ) as mock_ensure_group, patch(
        "desktop_manager.api.routes.oidc_routes.add_user_to_group"
    ) as mock_add_user, patch(
        "desktop_manager.api.routes.oidc_routes.create_guacamole_user"
    ) as mock_create_user, patch(
        "desktop_manager.api.routes.oidc_routes.update_guacamole_user"
    ) as mock_update_user:
        mock_ensure_group.return_value = None
        mock_add_user.return_value = None
        mock_create_user.return_value = None
        mock_update_user.return_value = None
        yield {
            "ensure_group": mock_ensure_group,
            "add_user": mock_add_user,
            "create_user": mock_create_user,
            "update_user": mock_update_user,
        }


@pytest.fixture()
def mock_pkce_verifier():
    """Mock a PKCE code verifier."""
    # Return a fixed code verifier for testing
    return "test_code_verifier"


@pytest.fixture()
def mock_pkce_challenge(mock_pkce_verifier):
    """Generate a PKCE code challenge from the mock verifier."""
    # Generate the S256 challenge method
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(mock_pkce_verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return code_challenge


@pytest.fixture()
def mock_oidc_userinfo():
    """Mock OIDC userinfo response."""
    return {
        "sub": "test_subject_id",
        "email": "test.user@example.com",
        "name": "Test User",
        "family_name": "User",
        "given_name": "Test",
        "preferred_username": "test_user",
        "organization": "Test Organization",
    }


@pytest.fixture()
def stored_pkce_state(test_db):
    """Create a test PKCE state in the database."""
    state = secrets.token_urlsafe(32)
    code_verifier = "test_code_verifier"
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)

    pkce_state = PKCEState(
        state=state, code_verifier=code_verifier, expires_at=expires_at
    )
    test_db.add(pkce_state)
    test_db.commit()
    test_db.refresh(pkce_state)
    return pkce_state


# OIDC Login Tests
def test_oidc_login_success(test_client):
    """Test successful OIDC login initiation."""
    response = test_client.get("/auth/oidc/login")

    assert response.status_code == HTTPStatus.OK
    response_data = response.get_json()

    # Check response contains auth_url and state
    assert "auth_url" in response_data
    assert "state" in response_data

    # Verify auth_url format and parameters
    auth_url = response_data["auth_url"]
    parsed_url = urlparse(auth_url)
    assert parsed_url.scheme == "https"
    assert "oidc.test" in parsed_url.netloc
    assert "/authorize" in parsed_url.path

    # Check query parameters
    query_params = parse_qs(parsed_url.query)
    assert "client_id" in query_params
    assert "redirect_uri" in query_params
    assert "state" in query_params
    assert "code_challenge" in query_params
    assert "code_challenge_method" in query_params
    assert query_params["code_challenge_method"][0] == "S256"


def test_oidc_login_db_failure(test_client, test_db):
    """Test OIDC login with database failure."""
    # Patch the add method to raise an exception
    with patch.object(test_db, "add", side_effect=Exception("Database error")):
        response = test_client.get("/auth/oidc/login")

        assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
        response_data = response.get_json()
        assert "error" in response_data
        assert "Database error" in response_data["error"]


# OIDC Callback Tests
def test_oidc_callback_success(test_client, stored_pkce_state, mock_guacamole):
    """Test successful OIDC callback handling."""
    # Mock successful token and userinfo responses
    with patch(
        "desktop_manager.api.routes.oidc_routes.requests.post"
    ) as mock_post, patch(
        "desktop_manager.api.routes.oidc_routes.requests.get"
    ) as mock_get:
        # Mock token response
        mock_token_response = Mock()
        mock_token_response.status_code = 200
        mock_token_response.json.return_value = {
            "access_token": "test_access_token",
            "id_token": "test_id_token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_post.return_value = mock_token_response

        # Mock userinfo response
        mock_userinfo_response = Mock()
        mock_userinfo_response.status_code = 200
        mock_userinfo_response.json.return_value = {
            "sub": "test_subject_id",
            "email": "test.user@example.com",
            "name": "Test User",
            "preferred_username": "oidc_test_user",
            "organization": "Test Organization",
        }
        mock_get.return_value = mock_userinfo_response

        # Make the callback request
        response = test_client.post(
            "/auth/oidc/callback",
            json={
                "code": "test_authorization_code",
                "state": stored_pkce_state.state,
                "redirect_uri": "http://test-callback-url.com",
            },
        )

        # Verify the response
        assert response.status_code == HTTPStatus.OK
        response_data = response.get_json()
        assert "token" in response_data
        assert "username" in response_data

        # Verify Guacamole mocks were called
        mock_guacamole["ensure_group"].assert_called_once()
        mock_guacamole["add_user"].assert_called_once()


def test_oidc_callback_missing_params(test_client):
    """Test OIDC callback with missing parameters."""
    # Test with missing code
    response = test_client.post(
        "/auth/oidc/callback",
        json={"state": "some_state", "redirect_uri": "http://test-callback-url.com"},
    )
    assert response.status_code == HTTPStatus.BAD_REQUEST

    # Test with missing state
    response = test_client.post(
        "/auth/oidc/callback",
        json={"code": "some_code", "redirect_uri": "http://test-callback-url.com"},
    )
    assert response.status_code == HTTPStatus.BAD_REQUEST

    # Test with missing redirect_uri
    response = test_client.post(
        "/auth/oidc/callback", json={"code": "some_code", "state": "some_state"}
    )
    assert response.status_code == HTTPStatus.BAD_REQUEST

    # Test with empty data
    response = test_client.post("/auth/oidc/callback", json={})
    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_oidc_callback_invalid_state(test_client):
    """Test OIDC callback with invalid state."""
    response = test_client.post(
        "/auth/oidc/callback",
        json={
            "code": "test_authorization_code",
            "state": "invalid_state",
            "redirect_uri": "http://test-callback-url.com",
        },
    )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    response_data = response.get_json()
    assert "error" in response_data
    assert "state" in response_data["error"].lower()


def test_oidc_callback_token_error(test_client, stored_pkce_state):
    """Test OIDC callback with token retrieval error."""
    with patch("desktop_manager.api.routes.oidc_routes.requests.post") as mock_post:
        # Simulate error response from token endpoint
        mock_error_response = Mock()
        mock_error_response.status_code = 400
        mock_error_response.text = json.dumps({"error": "invalid_grant"})
        mock_post.return_value = mock_error_response

        response = test_client.post(
            "/auth/oidc/callback",
            json={
                "code": "test_authorization_code",
                "state": stored_pkce_state.state,
                "redirect_uri": "http://test-callback-url.com",
            },
        )

        assert response.status_code == HTTPStatus.BAD_GATEWAY
        response_data = response.get_json()
        assert "error" in response_data
        assert "Token exchange failed" in response_data["error"]


def test_oidc_callback_userinfo_error(test_client, stored_pkce_state):
    """Test OIDC callback with userinfo retrieval error."""
    with patch(
        "desktop_manager.api.routes.oidc_routes.requests.post"
    ) as mock_post, patch(
        "desktop_manager.api.routes.oidc_routes.requests.get"
    ) as mock_get:
        # Mock successful token response
        mock_token_response = Mock()
        mock_token_response.status_code = 200
        mock_token_response.json.return_value = {
            "access_token": "test_access_token",
            "id_token": "test_id_token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_post.return_value = mock_token_response

        # Mock userinfo endpoint raising an exception
        mock_get.side_effect = requests.exceptions.RequestException("Userinfo error")

        response = test_client.post(
            "/auth/oidc/callback",
            json={
                "code": "test_authorization_code",
                "state": stored_pkce_state.state,
                "redirect_uri": "http://test-callback-url.com",
            },
        )

        assert response.status_code == HTTPStatus.BAD_GATEWAY
        response_data = response.get_json()
        assert "error" in response_data
        assert "OIDC provider error" in response_data["error"]


def test_oidc_callback_missing_user_fields(test_client, stored_pkce_state):
    """Test OIDC callback with missing user fields in userinfo."""
    with patch(
        "desktop_manager.api.routes.oidc_routes.requests.post"
    ) as mock_post, patch(
        "desktop_manager.api.routes.oidc_routes.requests.get"
    ) as mock_get:
        # Mock successful token response
        mock_token_response = Mock()
        mock_token_response.status_code = 200
        mock_token_response.json.return_value = {
            "access_token": "test_access_token",
            "id_token": "test_id_token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_post.return_value = mock_token_response

        # Mock userinfo response with missing required field (email)
        mock_userinfo_response = Mock()
        mock_userinfo_response.status_code = 200
        mock_userinfo_response.json.return_value = {
            "sub": "test_subject_id"
            # Missing email, which is required
        }
        mock_get.return_value = mock_userinfo_response

        response = test_client.post(
            "/auth/oidc/callback",
            json={
                "code": "test_authorization_code",
                "state": stored_pkce_state.state,
                "redirect_uri": "http://test-callback-url.com",
            },
        )

        assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
        response_data = response.get_json()
        assert "error" in response_data


def test_oidc_callback_existing_user(
    test_client, test_db, stored_pkce_state, mock_guacamole
):
    """Test OIDC callback for an existing user."""
    # Create a user with the same OIDC subject ID
    existing_user = User(
        username="existing_oidc_user",
        email="existing@example.com",
        organization="Existing Org",
        sub="test_subject_id",
    )
    test_db.add(existing_user)
    test_db.commit()
    test_db.refresh(existing_user)

    # Create the social auth association
    association = SocialAuthAssociation(
        user_id=existing_user.id, provider="oidc", provider_user_id="test_subject_id"
    )
    test_db.add(association)
    test_db.commit()

    # Mock successful token and userinfo responses
    with patch(
        "desktop_manager.api.routes.oidc_routes.requests.post"
    ) as mock_post, patch(
        "desktop_manager.api.routes.oidc_routes.requests.get"
    ) as mock_get:
        # Mock token response
        mock_token_response = Mock()
        mock_token_response.status_code = 200
        mock_token_response.json.return_value = {
            "access_token": "test_access_token",
            "id_token": "test_id_token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_post.return_value = mock_token_response

        # Mock userinfo response (this username is different from the existing user)
        mock_userinfo_response = Mock()
        mock_userinfo_response.status_code = 200
        mock_userinfo_response.json.return_value = {
            "sub": "test_subject_id",
            "email": "existing@example.com",
            "name": "Updated User",
            "preferred_username": "updated_user",
            "organization": "Updated Organization",
        }
        mock_get.return_value = mock_userinfo_response

        # Make the callback request
        response = test_client.post(
            "/auth/oidc/callback",
            json={
                "code": "test_authorization_code",
                "state": stored_pkce_state.state,
                "redirect_uri": "http://test-callback-url.com",
            },
        )

        # Verify the response
        assert response.status_code == HTTPStatus.OK
        response_data = response.get_json()
        assert "token" in response_data
        assert "username" in response_data

        # Verify Guacamole mocks were not called for existing users
        assert not mock_guacamole["ensure_group"].called
        assert not mock_guacamole["add_user"].called


def test_oidc_callback_error_in_response(test_client):
    """Test OIDC callback when error is returned in the callback."""
    response = test_client.post(
        "/auth/oidc/callback",
        json={
            "error": "access_denied",
            "error_description": "The user denied the request",
        },
    )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    response_data = response.get_json()
    assert "error" in response_data
    assert "Missing code, state, or redirect_uri parameter" in response_data["error"]


def test_oidc_callback_network_error(test_client, stored_pkce_state):
    """Test OIDC callback when a network error occurs."""
    with patch(
        "desktop_manager.api.routes.oidc_routes.requests.post",
        side_effect=requests.exceptions.RequestException("Network error"),
    ):
        response = test_client.post(
            "/auth/oidc/callback",
            json={
                "code": "test_authorization_code",
                "state": stored_pkce_state.state,
                "redirect_uri": "http://test-callback-url.com",
            },
        )

        assert response.status_code == HTTPStatus.BAD_GATEWAY
        response_data = response.get_json()
        assert "error" in response_data
        assert "OIDC provider error" in response_data["error"]
