"""Unit tests for authentication functionality."""

import json
from typing import Generator
from unittest.mock import patch

import pytest
import requests
import responses
from fakeredis import FakeStrictRedis
from flask import Flask, session, url_for
from flask.testing import FlaskClient

from tests.config import TestConfig
from tests.conftest import TEST_ADMIN, TEST_TOKEN, TEST_USER


@pytest.fixture()
def mock_api_auth(responses_mock: responses.RequestsMock) -> Generator:
    """Mock authentication API endpoints."""
    base_url = TestConfig.API_URL

    # Mock successful login
    responses_mock.add(
        responses.POST,
        f"{base_url}/api/auth/login",
        json={
            "token": TEST_TOKEN,
            "username": TEST_USER["username"],
            "is_admin": TEST_USER["is_admin"],
        },
        status=200,
        match=[
            responses.matchers.json_params_matcher(
                {"username": TEST_USER["username"], "password": TEST_USER["password"]}
            )
        ],
    )

    # Mock failed login
    responses_mock.add(
        responses.POST,
        f"{base_url}/api/auth/login",
        json={"error": "Invalid credentials"},
        status=401,
        match=[
            responses.matchers.json_params_matcher(
                {"username": "wronguser", "password": "wrongpass"}
            )
        ],
    )

    return responses_mock


def test_login_success(client: FlaskClient, responses_mock) -> None:
    """Test successful login."""
    responses_mock.add(
        responses_mock.POST,
        f"{TestConfig.API_URL}/api/auth/login",
        json={
            "token": TEST_TOKEN,
            "username": TEST_USER["username"],
            "is_admin": TEST_USER["is_admin"],
        },
        status=200,
    )

    response = client.post(
        "/auth/login",
        json={"username": TEST_USER["username"], "password": TEST_USER["password"]},
        follow_redirects=False,
    )

    assert response.status_code == 302  # Should be a redirect
    with client.session_transaction() as sess:
        assert sess["token"] == TEST_TOKEN
        assert sess["username"] == TEST_USER["username"]
        assert sess["is_admin"] == TEST_USER["is_admin"]


def test_login_admin_success(client: FlaskClient, responses_mock) -> None:
    """Test successful admin login."""
    responses_mock.add(
        responses_mock.POST,
        f"{TestConfig.API_URL}/api/auth/login",
        json={
            "token": TEST_TOKEN,
            "username": TEST_ADMIN["username"],
            "is_admin": TEST_ADMIN["is_admin"],
        },
        status=200,
    )

    response = client.post(
        "/auth/login",
        json={"username": TEST_ADMIN["username"], "password": TEST_ADMIN["password"]},
        follow_redirects=False,
    )

    assert response.status_code == 302  # Should be a redirect
    with client.session_transaction() as sess:
        assert sess["token"] == TEST_TOKEN
        assert sess["username"] == TEST_ADMIN["username"]
        assert sess["is_admin"] == TEST_ADMIN["is_admin"]


def test_login_failure(client: FlaskClient, responses_mock) -> None:
    """Test failed login."""
    responses_mock.add(
        responses_mock.POST,
        f"{TestConfig.API_URL}/api/auth/login",
        json={"error": "Invalid credentials"},
        status=401,
    )

    response = client.post(
        "/auth/login", json={"username": "wronguser", "password": "wrongpass"}
    )

    assert response.status_code == 401
    assert response.is_json
    assert "error" in response.json
    assert response.json["error"] == "Invalid credentials"


def test_login_missing_credentials(client: FlaskClient) -> None:
    """Test login with missing credentials."""
    response = client.post("/auth/login", json={})
    assert response.status_code == 400
    assert response.is_json
    assert "error" in response.json
    assert response.json["error"] == "Missing required fields"


def test_logout(client: FlaskClient) -> None:
    """Test logout functionality."""
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_USER["username"]
        sess["is_admin"] = TEST_USER["is_admin"]
        sess["logged_in"] = True

    response = client.get("/auth/logout", follow_redirects=True)
    assert response.status_code == 200

    with client.session_transaction() as sess:
        assert "token" not in sess
        assert "username" not in sess
        assert "is_admin" not in sess


def test_login_rate_limit(client: FlaskClient, responses_mock) -> None:
    """Test login rate limiting."""
    responses_mock.add(
        responses_mock.POST,
        f"{TestConfig.API_URL}/api/auth/login",
        json={"error": "Rate limit exceeded"},
        status=429,
    )

    # Make multiple requests to trigger rate limit
    for _ in range(6):  # Exceeds the rate limit of 5 requests per minute
        response = client.post(
            "/auth/login",
            json={"username": TEST_USER["username"], "password": TEST_USER["password"]},
        )

    assert response.status_code == 429
    assert b"Too many requests" in response.data


def test_oidc_login_success(client: FlaskClient, responses_mock) -> None:
    """Test successful OIDC login initiation."""
    responses_mock.add(
        responses_mock.GET,
        f"{TestConfig.API_URL}/api/auth/oidc/login",
        json={"auth_url": "http://test-oidc-provider/auth"},
        status=200,
    )

    response = client.get("/auth/oidc/login")
    assert response.status_code == 302  # Should redirect to auth URL
    assert response.headers["Location"] == "http://test-oidc-provider/auth"


def test_oidc_login_failure(client: FlaskClient, responses_mock) -> None:
    """Test failed OIDC login initiation."""
    responses_mock.add(
        responses_mock.GET,
        f"{TestConfig.API_URL}/api/auth/oidc/login",
        json={"error": "OIDC provider unavailable"},
        status=500,
    )

    response = client.get("/auth/oidc/login", follow_redirects=True)
    assert response.status_code == 200  # Should redirect to login page
    assert b"Failed to initiate login" in response.data


def test_oidc_callback_success(client: FlaskClient, responses_mock) -> None:
    """Test successful OIDC callback."""
    callback_url = "http://localhost:5001/auth/oidc/callback"  # Match the URL used in the code
    responses_mock.add(
        responses_mock.POST,
        f"{TestConfig.API_URL}/api/auth/oidc/callback",
        match=[
            responses.matchers.json_params_matcher(
                {
                    "code": "test-code",
                    "state": "test-state",
                    "redirect_uri": callback_url,
                }
            )
        ],
        json={
            "token": TEST_TOKEN,
            "username": TEST_USER["username"],
            "is_admin": TEST_USER["is_admin"],
            # Not all tests might be accessing these fields
            # so it's fine if they're missing in some responses
        },
        status=200,
    )

    with client.session_transaction() as sess:
        sess["next_url"] = "/connections"  # Set next URL to test redirect

    client.application.config["SERVER_NAME"] = "localhost:5001"  # Match used port

    response = client.get(
        "/auth/oidc/callback?code=test-code&state=test-state", follow_redirects=False
    )
    assert response.status_code == 302  # Should redirect to next URL

    with client.session_transaction() as sess:
        assert sess["token"] == TEST_TOKEN
        assert sess["username"] == TEST_USER["username"]
        assert sess["is_admin"] == TEST_USER["is_admin"]
        # Don't check for email or other optional fields
        assert sess.permanent is True


def test_oidc_callback_error_in_params(client: FlaskClient) -> None:
    """Test OIDC callback with error in parameters."""
    response = client.get(
        "/auth/oidc/callback?error=access_denied&error_description=User+cancelled",
        follow_redirects=True,
    )
    assert response.status_code == 200  # Should redirect to login page
    assert b"Authentication failed: User cancelled" in response.data


def test_oidc_callback_missing_params(client: FlaskClient) -> None:
    """Test OIDC callback with missing parameters."""
    response = client.get("/auth/oidc/callback", follow_redirects=True)
    assert response.status_code == 200  # Should redirect to login page
    assert b"Invalid callback parameters" in response.data


def test_oidc_callback_failure(client: FlaskClient, responses_mock) -> None:
    """Test failed OIDC callback."""
    responses_mock.add(
        responses_mock.POST,
        f"{TestConfig.API_URL}/api/auth/oidc/callback",
        json={"error": "Invalid code"},
        status=400,
    )

    response = client.get(
        "/auth/oidc/callback?code=invalid-code&state=test-state", follow_redirects=True
    )
    assert response.status_code == 200  # Should redirect to login page
    assert b"Authentication failed" in response.data


def test_oidc_callback_network_error(client: FlaskClient, responses_mock) -> None:
    """Test OIDC callback with network error."""
    responses_mock.add(
        responses_mock.POST,
        f"{TestConfig.API_URL}/api/auth/oidc/callback",
        body=requests.exceptions.ConnectionError(),
    )

    response = client.get(
        "/auth/oidc/callback?code=test-code&state=test-state", follow_redirects=True
    )
    assert response.status_code == 200  # Should redirect to login page
    assert b"Error completing authentication" in response.data
