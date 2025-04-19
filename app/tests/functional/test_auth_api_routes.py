"""
This module contains functional tests for the authentication API routes.
"""
import json
from unittest.mock import patch, MagicMock
from http import HTTPStatus

import pytest


def test_auth_status_not_authenticated(client):
    """
    GIVEN a Flask application with an unauthenticated client
    WHEN the auth status endpoint is called
    THEN check that the correct response is returned
    """
    response = client.get("/api/auth/status")

    assert response.status_code == HTTPStatus.OK
    data = json.loads(response.data)
    assert data["authenticated"] is False


def test_auth_status_authenticated(logged_in_client):
    """
    GIVEN a Flask application with an authenticated client
    WHEN the auth status endpoint is called
    THEN check that the correct user data is returned
    """
    # First set up the session data
    with logged_in_client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["token"] = "test-token"
        sess["username"] = "test_user"
        sess["is_admin"] = False
        sess["email"] = "test@example.com"

    response = logged_in_client.get("/api/auth/status")

    assert response.status_code == HTTPStatus.OK
    data = json.loads(response.data)
    assert data["authenticated"] is True
    assert "user" in data
    assert data["user"]["username"] == "test_user"
    assert data["user"]["is_admin"] is False
    assert data["user"]["email"] == "test@example.com"
