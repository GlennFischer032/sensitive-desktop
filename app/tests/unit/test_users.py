"""Unit tests for user management functionality."""

import logging

import pytest
import requests
import responses
from flask import Flask, session
from flask.testing import FlaskClient

from tests.conftest import TEST_ADMIN, TEST_TOKEN, TEST_USER

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def test_view_users_success(client: FlaskClient, responses_mock) -> None:
    """Test successful users listing for admin."""
    # Set up admin session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_ADMIN["username"]
        sess["is_admin"] = TEST_ADMIN["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    logger.debug(
        f"Session after setup: token={TEST_TOKEN[:10]}..., is_admin={TEST_ADMIN['is_admin']}"
    )

    # Mock successful API response
    responses_mock.add(
        responses_mock.GET,
        "http://test-api:5000/api/users/list",
        match=[
            responses_mock.matchers.header_matcher(
                {"Authorization": f"Bearer {TEST_TOKEN}"}
            )
        ],
        json={
            "users": [
                {"username": "user1", "email": "user1@test.com", "is_admin": False},
                {"username": "user2", "email": "user2@test.com", "is_admin": True},
            ]
        },
        status=200,
    )

    # Mock the JWT decode function to ensure token verification passes
    with pytest.MonkeyPatch.context() as mp:
        from datetime import datetime, timedelta

        import jwt

        def mock_decode(*args, **kwargs):
            # Return a valid token payload that won't expire
            exp_time = (datetime.utcnow() + timedelta(hours=1)).timestamp()
            return {
                "username": TEST_ADMIN["username"],
                "is_admin": TEST_ADMIN["is_admin"],
                "exp": exp_time,
            }

        # Override the jwt.decode function
        mp.setattr(jwt, "decode", mock_decode)

        logger.debug("Making request to /users/ with mocked JWT")
        response = client.get("/users/")
        logger.debug(f"Response status code: {response.status_code}")
        logger.debug(f"Response headers: {response.headers}")
        if response.status_code == 302:
            logger.debug(f"Redirect location: {response.headers.get('Location')}")

        assert response.status_code == 200
        assert b"user1@test.com" in response.data
        assert b"user2@test.com" in response.data


def test_view_users_non_admin(client: FlaskClient) -> None:
    """Test users listing access denied for non-admin."""
    # Set up non-admin session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_USER["username"]
        sess["is_admin"] = TEST_USER["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    response = client.get("/users/")
    assert response.status_code == 302  # Redirect to connections page


def test_view_users_api_error(client: FlaskClient, responses_mock) -> None:
    """Test users listing with API error."""
    # Set up admin session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_ADMIN["username"]
        sess["is_admin"] = TEST_ADMIN["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    # Mock API error response
    responses_mock.add(
        responses_mock.GET,
        "http://test-api:5000/api/users/list",
        json={"error": "Internal server error"},
        status=500,
    )

    response = client.get("/users/")
    assert response.status_code == 200
    assert b"Failed to fetch users" in response.data


def test_add_user_get(client: FlaskClient) -> None:
    """Test get add user page."""
    # Set up admin session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_ADMIN["username"]
        sess["is_admin"] = TEST_ADMIN["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    response = client.get("/users/add")
    assert response.status_code == 200
    assert b"Add User" in response.data


def test_add_user_success(client: FlaskClient, responses_mock) -> None:
    """Test successful user addition."""
    # Set up admin session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_ADMIN["username"]
        sess["is_admin"] = TEST_ADMIN["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    # Mock successful API response
    responses_mock.add(
        responses_mock.POST,
        "http://test-api:5000/api/users/createuser",
        match=[
            responses_mock.matchers.header_matcher(
                {
                    "Authorization": f"Bearer {TEST_TOKEN}",
                    "Content-Type": "application/json",
                }
            ),
            responses_mock.matchers.json_params_matcher(
                {
                    "username": "newuser",
                    "is_admin": False,
                    "sub": "user123456",
                }
            ),
        ],
        json={"message": "User created"},
        status=201,
    )

    response = client.post(
        "/users/add",
        data={
            "username": "newuser",
            "sub": "user123456",
            "is_admin": "false",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"User added successfully" in response.data


def test_add_user_missing_fields(client: FlaskClient) -> None:
    """Test add user with missing required fields."""
    # Set up admin session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_ADMIN["username"]
        sess["is_admin"] = TEST_ADMIN["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    response = client.post("/users/add", data={}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Username and OIDC Subject Identifier are required" in response.data


def test_add_user_validation_error(client: FlaskClient, responses_mock) -> None:
    """Test add user with API validation error."""
    # Set up admin session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_ADMIN["username"]
        sess["is_admin"] = TEST_ADMIN["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    # Mock API validation error response
    responses_mock.add(
        responses_mock.POST,
        "http://test-api:5000/api/users/createuser",
        json={
            "error": "Validation error",
            "details": {
                "sub": ["Invalid subject identifier"],
            },
        },
        status=400,
    )

    response = client.post(
        "/users/add",
        data={
            "username": "newuser",
            "sub": "invalid-sub",
            "is_admin": "false",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Sub: Invalid subject identifier" in response.data


def test_add_user_network_error(client: FlaskClient, responses_mock) -> None:
    """Test add user with network error."""
    # Set up admin session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_ADMIN["username"]
        sess["is_admin"] = TEST_ADMIN["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    # Mock network error
    responses_mock.add(
        responses_mock.POST,
        "http://test-api:5000/api/users/createuser",
        body=Exception("Network error"),
    )

    response = client.post(
        "/users/add",
        data={
            "username": "newuser",
            "sub": "user123456",
            "is_admin": "false",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Error: Network error" in response.data


def test_add_user_timeout(client: FlaskClient, responses_mock) -> None:
    """Test add user with API timeout."""
    # Set up admin session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_ADMIN["username"]
        sess["is_admin"] = TEST_ADMIN["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    # Mock timeout error
    responses_mock.add(
        responses_mock.POST,
        "http://test-api:5000/api/users/createuser",
        body=requests.exceptions.Timeout("Request timed out"),
    )

    response = client.post(
        "/users/add",
        data={
            "username": "newuser",
            "sub": "user123456",
            "is_admin": "false",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Failed to add user: Request timed out after 10 seconds" in response.data


def test_delete_user_success(client: FlaskClient, responses_mock) -> None:
    """Test successful user deletion."""
    # Set up admin session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_ADMIN["username"]
        sess["is_admin"] = TEST_ADMIN["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    # Mock successful API response
    responses_mock.add(
        responses_mock.POST,
        "http://test-api:5000/api/users/removeuser",
        match=[
            responses_mock.matchers.header_matcher(
                {
                    "Authorization": f"Bearer {TEST_TOKEN}",
                    "Content-Type": "application/json",
                }
            ),
            responses_mock.matchers.json_params_matcher({"username": "testuser"}),
        ],
        json={"message": "User deleted"},
        status=200,
    )

    response = client.post("/users/delete/testuser", follow_redirects=True)
    assert response.status_code == 200
    assert b"User deleted successfully" in response.data


def test_delete_self(client: FlaskClient) -> None:
    """Test attempting to delete own account."""
    # Set up admin session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_ADMIN["username"]
        sess["is_admin"] = TEST_ADMIN["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    response = client.post(
        f"/users/delete/{TEST_ADMIN['username']}", follow_redirects=True
    )
    assert response.status_code == 200
    assert b"Cannot delete your own account" in response.data


def test_delete_user_network_error(client: FlaskClient, responses_mock) -> None:
    """Test delete user with network error."""
    # Set up admin session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_ADMIN["username"]
        sess["is_admin"] = TEST_ADMIN["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    # Mock network error
    responses_mock.add(
        responses_mock.POST,
        "http://test-api:5000/api/users/removeuser",
        body=Exception("Network error"),
    )

    response = client.post("/users/delete/testuser", follow_redirects=True)
    assert response.status_code == 200
    assert b"Error:" in response.data


def test_dashboard_success(client: FlaskClient) -> None:
    """Test successful dashboard access."""
    # Set up admin session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_ADMIN["username"]
        sess["is_admin"] = TEST_ADMIN["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    response = client.get("/users/dashboard")
    assert response.status_code == 200
    assert b"Welcome to Desktop Manager" in response.data
    assert b"Manage your desktop connections" in response.data
    assert b"Manage system users" in response.data


def test_dashboard_api_error(client: FlaskClient, responses_mock) -> None:
    """Test dashboard with API error."""
    # Set up admin session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_ADMIN["username"]
        sess["is_admin"] = TEST_ADMIN["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    # Mock API error response
    responses_mock.add(
        responses_mock.GET,
        "http://test-api:5000/api/users/list",
        json={"error": "Internal server error"},
        status=500,
    )

    response = client.get("/users/dashboard")
    assert response.status_code == 200
    assert b"Failed to fetch users list" in response.data


def test_dashboard_network_error(client: FlaskClient, responses_mock) -> None:
    """Test dashboard with network error."""
    # Set up admin session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_ADMIN["username"]
        sess["is_admin"] = TEST_ADMIN["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    # Mock network error
    responses_mock.add(
        responses_mock.GET,
        "http://test-api:5000/api/users/list",
        body=Exception("Network error"),
    )

    response = client.get("/users/dashboard")
    assert response.status_code == 200
    assert b"Error fetching users list" in response.data


def test_remove_user_ajax(client: FlaskClient, responses_mock) -> None:
    """Test successful user removal via AJAX."""
    # Set up admin session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_ADMIN["username"]
        sess["is_admin"] = TEST_ADMIN["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    # Mock successful API response
    responses_mock.add(
        responses_mock.POST,
        "http://test-api:5000/api/users/removeuser",
        match=[
            responses_mock.matchers.header_matcher(
                {
                    "Authorization": f"Bearer {TEST_TOKEN}",
                    "Content-Type": "application/json",
                }
            ),
            responses_mock.matchers.json_params_matcher({"username": "testuser"}),
        ],
        json={"message": "User removed"},
        status=200,
    )

    response = client.post(
        "/users/remove/testuser",
        headers={
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 200
    assert response.is_json
    assert response.json["status"] == "success"


def test_remove_user_network_error(client: FlaskClient, responses_mock) -> None:
    """Test remove user with network error."""
    # Set up admin session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_ADMIN["username"]
        sess["is_admin"] = TEST_ADMIN["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    # Mock network error
    responses_mock.add(
        responses_mock.POST,
        "http://test-api:5000/api/users/removeuser",
        body=Exception("Network error"),
    )

    # Test AJAX request
    response = client.post(
        "/users/remove/testuser",
        headers={
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/json",
        },
        json={"username": "testuser"},
    )
    assert response.status_code == 200
    assert response.is_json
    assert response.json["status"] == "success"


def test_remove_self_ajax(client: FlaskClient) -> None:
    """Test attempting to remove own account via AJAX."""
    # Set up admin session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_ADMIN["username"]
        sess["is_admin"] = TEST_ADMIN["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    response = client.post(
        f"/users/remove/{TEST_ADMIN['username']}",
        headers={
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/json",
        },
        json={"username": TEST_ADMIN["username"]},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Cannot remove your own account" in response.data


def test_add_user_without_password(client: FlaskClient, responses_mock) -> None:
    """Test successful user addition without a password (for OIDC users)."""
    # Set up admin session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_ADMIN["username"]
        sess["is_admin"] = TEST_ADMIN["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    # Mock successful API response
    responses_mock.add(
        responses_mock.POST,
        "http://test-api:5000/api/users/createuser",
        match=[
            responses_mock.matchers.header_matcher(
                {
                    "Authorization": f"Bearer {TEST_TOKEN}",
                    "Content-Type": "application/json",
                }
            ),
            responses_mock.matchers.json_params_matcher(
                {
                    "username": "oidcuser",
                    "is_admin": False,
                    "sub": "oidc123456",
                }
            ),
        ],
        json={"message": "User created"},
        status=201,
    )

    response = client.post(
        "/users/add",
        data={
            "username": "oidcuser",
            "sub": "oidc123456",
            "is_admin": "false",
            # No password provided
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"User added successfully" in response.data


def test_delete_user_client_method(client: FlaskClient, responses_mock) -> None:
    """Test that the UsersClient.delete_user method correctly uses the /api/users/removeuser endpoint."""
    # Import the client factory
    from clients.factory import client_factory

    # Set up admin session with token
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_ADMIN["username"]
        sess["is_admin"] = TEST_ADMIN["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    # Mock successful API response
    responses_mock.add(
        responses_mock.POST,
        "http://test-api:5000/api/users/removeuser",
        match=[
            responses_mock.matchers.header_matcher(
                {
                    "Authorization": f"Bearer {TEST_TOKEN}",
                    "Content-Type": "application/json",
                }
            ),
            responses_mock.matchers.json_params_matcher({"username": "testuser"}),
        ],
        json={"message": "User deleted"},
        status=200,
    )

    # Get the users client and call delete_user directly with the token
    users_client = client_factory.get_users_client()
    result = users_client.delete_user("testuser", token=TEST_TOKEN)

    # Verify the result
    assert result == {"message": "User deleted"}

    # Verify that the mock was called
    assert len(responses_mock.calls) == 1
    assert responses_mock.calls[0].request.url == "http://test-api:5000/api/users/removeuser"
