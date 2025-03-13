"""Unit tests for connections functionality."""

import pytest
import responses
from flask import Flask, session
from flask.testing import FlaskClient

from tests.conftest import TEST_TOKEN, TEST_USER


def test_view_connections_success(client: FlaskClient, responses_mock) -> None:
    """Test successful connections listing."""
    # Set up session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_USER["username"]
        sess["is_admin"] = TEST_USER["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    # Mock successful API response
    responses_mock.add(
        responses_mock.GET,
        "http://test-api:5000/api/connections/list",
        match=[
            responses_mock.matchers.header_matcher(
                {"Authorization": f"Bearer {TEST_TOKEN}"}
            )
        ],
        json={
            "connections": [
                {"name": "test-conn-1", "status": "running"},
                {"name": "test-conn-2", "status": "stopped"},
            ]
        },
        status=200,
    )

    response = client.get("/connections/")
    assert response.status_code == 200
    assert b"test-conn-1" in response.data
    assert b"test-conn-2" in response.data


def test_view_connections_api_error(client: FlaskClient, responses_mock) -> None:
    """Test connections listing with API error."""
    # Set up session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_USER["username"]
        sess["is_admin"] = TEST_USER["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    # Mock API error response
    responses_mock.add(
        responses_mock.GET,
        "http://test-api:5000/api/connections/list",
        json={"error": "Internal server error"},
        status=500,
    )

    response = client.get("/connections/")
    assert response.status_code == 200
    assert b"Failed to fetch connections" in response.data


def test_view_connections_network_error(client: FlaskClient, responses_mock) -> None:
    """Test connections listing with network error."""
    # Set up session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_USER["username"]
        sess["is_admin"] = TEST_USER["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    # Mock network error
    responses_mock.add(
        responses_mock.GET,
        "http://test-api:5000/api/connections/list",
        body=Exception("Network error"),
    )

    response = client.get("/connections/")
    assert response.status_code == 200
    assert b"Error fetching connections" in response.data


def test_add_connection_get(client: FlaskClient) -> None:
    """Test get add connection page."""
    # Set up session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_USER["username"]
        sess["is_admin"] = TEST_USER["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    response = client.get("/connections/add")
    assert response.status_code == 200
    assert b"Add Connection" in response.data


def test_add_connection_success(client: FlaskClient, responses_mock) -> None:
    """Test successful connection addition."""
    # Set up session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_USER["username"]
        sess["is_admin"] = TEST_USER["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    # Mock successful API response
    responses_mock.add(
        responses_mock.POST,
        "http://test-api:5000/api/connections/scaleup",
        match=[
            responses_mock.matchers.header_matcher(
                {
                    "Authorization": f"Bearer {TEST_TOKEN}",
                    "Content-Type": "application/json",
                }
            ),
            responses_mock.matchers.json_params_matcher({"name": "test-connection"}),
        ],
        json={"message": "Connection created"},
        status=200,
    )

    response = client.post(
        "/connections/add",
        data={"connection_name": "test-connection"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Connection added successfully" in response.data


def test_add_connection_missing_name(client: FlaskClient) -> None:
    """Test add connection with missing name."""
    # Set up session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_USER["username"]
        sess["is_admin"] = TEST_USER["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    response = client.post("/connections/add", data={})
    assert response.status_code == 200
    assert b"Please provide a connection name" in response.data


def test_add_connection_api_error(client: FlaskClient, responses_mock) -> None:
    """Test add connection with API error."""
    # Set up session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_USER["username"]
        sess["is_admin"] = TEST_USER["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    # Mock API error response
    responses_mock.add(
        responses_mock.POST,
        "http://test-api:5000/api/connections/scaleup",
        json={"error": "Failed to create connection"},
        status=500,
    )

    response = client.post(
        "/connections/add",
        data={"connection_name": "test-connection"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Failed to add connection" in response.data


def test_add_connection_network_error(client: FlaskClient, responses_mock) -> None:
    """Test add connection with network error."""
    # Set up session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_USER["username"]
        sess["is_admin"] = TEST_USER["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    # Mock network error
    responses_mock.add(
        responses_mock.POST,
        "http://test-api:5000/api/connections/scaleup",
        body=Exception("Network error"),
    )

    response = client.post(
        "/connections/add",
        data={"connection_name": "test-connection"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Error adding connection" in response.data


def test_delete_connection_success(client: FlaskClient, responses_mock) -> None:
    """Test successful connection deletion."""
    # Set up session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_USER["username"]
        sess["is_admin"] = TEST_USER["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    # Mock successful API response
    responses_mock.add(
        responses_mock.POST,
        "http://test-api:5000/api/connections/scaledown",
        match=[
            responses_mock.matchers.header_matcher(
                {
                    "Authorization": f"Bearer {TEST_TOKEN}",
                    "Content-Type": "application/json",
                }
            ),
            responses_mock.matchers.json_params_matcher({"name": "test-connection"}),
        ],
        json={"message": "Connection deleted"},
        status=200,
    )

    response = client.post("/connections/delete/test-connection", follow_redirects=True)
    assert response.status_code == 200
    assert b"Connection deleted successfully" in response.data


def test_delete_connection_ajax(client: FlaskClient, responses_mock) -> None:
    """Test successful connection deletion via AJAX."""
    # Set up session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_USER["username"]
        sess["is_admin"] = TEST_USER["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    # Mock successful API response
    responses_mock.add(
        responses_mock.POST,
        "http://test-api:5000/api/connections/scaledown",
        json={"message": "Connection deleted"},
        status=200,
    )

    response = client.post(
        "/connections/delete/test-connection",
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    assert response.status_code == 200
    assert response.is_json
    assert response.json["status"] == "success"


def test_delete_connection_api_error(client: FlaskClient, responses_mock) -> None:
    """Test delete connection with API error."""
    # Set up session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_USER["username"]
        sess["is_admin"] = TEST_USER["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    # Mock API error response
    responses_mock.add(
        responses_mock.POST,
        "http://test-api:5000/api/connections/scaledown",
        json={"error": "Failed to delete connection"},
        status=500,
    )

    response = client.post("/connections/delete/test-connection", follow_redirects=True)
    assert response.status_code == 200
    assert b"Failed to delete connection" in response.data


def test_delete_connection_network_error(client: FlaskClient, responses_mock) -> None:
    """Test delete connection with network error."""
    # Set up session
    with client.session_transaction() as sess:
        sess["token"] = TEST_TOKEN
        sess["username"] = TEST_USER["username"]
        sess["is_admin"] = TEST_USER["is_admin"]
        sess["logged_in"] = True
        sess.permanent = True

    # Mock network error
    responses_mock.add(
        responses_mock.POST,
        "http://test-api:5000/api/connections/scaledown",
        body=Exception("Network error"),
    )

    response = client.post("/connections/delete/test-connection", follow_redirects=True)
    assert response.status_code == 200
    assert b"Error deleting connection" in response.data
