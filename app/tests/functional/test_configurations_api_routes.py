"""
This module contains functional tests for the Configuration API routes.
"""
import json
from unittest.mock import patch, MagicMock

from flask import url_for


def test_list_configurations_unauthorized(client):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/api/configurations/' page is requested without authentication
    THEN check the response is valid and redirects to login
    """
    response = client.get("/api/configurations/", follow_redirects=False)
    assert response.status_code == 403
    assert "You need to log in to access this page" in response.data.decode("utf-8")


def test_list_configurations_authenticated(logged_in_client):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/api/configurations/' page is requested by an authenticated user
    THEN check the response is valid
    """
    with patch("clients.factory.client_factory.get_desktop_configurations_client") as mock_client:
        # Setup mock response
        mock_config_client = MagicMock()
        mock_client.return_value = mock_config_client
        mock_config_client.list_configurations.return_value = [
            {"id": 1, "name": "Test Config", "description": "A test configuration", "is_public": True}
        ]

        # Make request
        response = logged_in_client.get("/api/configurations/")

        # Check response
        assert response.status_code == 200
        json_data = response.get_json()
        assert "configurations" in json_data
        assert len(json_data["configurations"]) == 1
        assert json_data["configurations"][0]["name"] == "Test Config"


def test_list_configurations_error(logged_in_client):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/api/configurations/' endpoint encounters an error
    THEN check the error is handled properly
    """
    with patch("clients.factory.client_factory.get_desktop_configurations_client") as mock_client:
        # Setup mock to raise error
        mock_config_client = MagicMock()
        mock_client.return_value = mock_config_client
        mock_config_client.list_configurations.side_effect = Exception("Test error")

        # Make request
        response = logged_in_client.get("/api/configurations/")

        # Check response
        assert response.status_code == 500
        json_data = response.get_json()
        assert "error" in json_data
        assert "Test error" in json_data["error"]


def test_get_configuration_success(logged_in_client):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/api/configurations/1' endpoint is requested
    THEN check the configuration is returned
    """
    with patch("clients.factory.client_factory.get_desktop_configurations_client") as mock_client:
        # Setup mock response
        mock_config_client = MagicMock()
        mock_client.return_value = mock_config_client
        mock_config_client.get_configuration.return_value = {
            "configuration": {"id": 1, "name": "Test Config", "description": "A test configuration", "is_public": True}
        }

        # Make request
        response = logged_in_client.get("/api/configurations/1")

        # Check response
        assert response.status_code == 200
        json_data = response.get_json()
        assert "configuration" in json_data
        assert json_data["configuration"]["id"] == 1
        assert json_data["configuration"]["name"] == "Test Config"


def test_get_configuration_not_found(logged_in_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a non-existent configuration is requested
    THEN check the error is handled properly
    """
    from clients.base import APIError

    with patch("clients.factory.client_factory.get_desktop_configurations_client") as mock_client:
        # Setup mock to raise error
        mock_config_client = MagicMock()
        mock_client.return_value = mock_config_client
        mock_config_client.get_configuration.side_effect = APIError("Configuration not found", status_code=404)

        # Make request
        response = logged_in_client.get("/api/configurations/999")

        # Check response
        assert response.status_code == 404
        json_data = response.get_json()
        assert "error" in json_data
        assert "Configuration not found" in json_data["error"]


def test_create_configuration_success(admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a new configuration is created
    THEN check it succeeds and returns the right response
    """
    with patch("clients.factory.client_factory.get_desktop_configurations_client") as mock_client:
        # Setup mock response
        mock_config_client = MagicMock()
        mock_client.return_value = mock_config_client

        # Test data
        config_data = {
            "name": "New Config",
            "description": "A new test configuration",
            "is_public": True,
            "min_cpu": 1,
            "max_cpu": 4,
            "min_ram": 2,
            "max_ram": 8,
        }

        # Make request
        response = admin_client.post(
            "/api/configurations/", data=json.dumps(config_data), content_type="application/json"
        )

        # Check response
        assert response.status_code == 201
        json_data = response.get_json()
        assert json_data["success"] is True
        assert json_data["message"] == "Configuration created successfully"

        # Verify correct data was passed to client
        mock_config_client.create_configuration.assert_called_once()
        call_kwargs = mock_config_client.create_configuration.call_args[1]
        assert call_kwargs["config_data"] == config_data


def test_create_configuration_missing_data(admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a configuration is created with missing data
    THEN check the appropriate error is returned
    """
    # Make request with empty data
    response = admin_client.post("/api/configurations/", data=json.dumps({}), content_type="application/json")

    # Check response - should return a 400 error as validation happens in the backend
    assert response.status_code == 400
    json_data = response.get_json()
    assert "error" in json_data


def test_create_configuration_non_admin(logged_in_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a non-admin tries to create a configuration
    THEN check access is denied (either by redirect or service unavailable response)
    """
    with patch("flask.session") as mock_session:
        # Make sure session is seen as not admin
        mock_session.get.side_effect = lambda k, *args: False if k == "is_admin" else None

        config_data = {"name": "New Config", "description": "A new test configuration"}

        response = logged_in_client.post(
            "/api/configurations/",
            data=json.dumps(config_data),
            content_type="application/json",
            follow_redirects=False,
        )

        # Should either redirect to login or show service unavailable
        # Both indicate the request was not processed as expected
        assert response.status_code == 403
        assert "You need administrator privileges" in response.data.decode("utf-8")


def test_update_configuration_success(admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a configuration is updated
    THEN check it succeeds and returns the right response
    """
    with patch("clients.factory.client_factory.get_desktop_configurations_client") as mock_client:
        # Setup mock response
        mock_config_client = MagicMock()
        mock_client.return_value = mock_config_client

        # Test data
        config_data = {"name": "Updated Config", "description": "Updated description", "is_public": False}

        # Make request
        response = admin_client.put(
            "/api/configurations/1", data=json.dumps(config_data), content_type="application/json"
        )

        # Check response
        assert response.status_code == 200
        json_data = response.get_json()
        assert json_data["success"] is True
        assert json_data["message"] == "Configuration updated successfully"

        # Verify correct data was passed to client
        mock_config_client.update_configuration.assert_called_once()
        call_kwargs = mock_config_client.update_configuration.call_args[1]
        assert call_kwargs["config_id"] == 1
        assert call_kwargs["config_data"] == config_data


def test_update_configuration_unauthorized(logged_in_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a non-admin tries to update a configuration
    THEN check access is denied (either by redirect or service unavailable response)
    """
    with patch("flask.session") as mock_session:
        # Make sure session is seen as not admin
        mock_session.get.side_effect = lambda k, *args: False if k == "is_admin" else None

        config_data = {"name": "Updated Config", "description": "Updated description"}

        response = logged_in_client.put(
            "/api/configurations/1",
            data=json.dumps(config_data),
            content_type="application/json",
            follow_redirects=False,
        )

        assert response.status_code == 403
        assert "You need administrator privileges" in response.data.decode("utf-8")


def test_delete_configuration_success(admin_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a configuration is deleted
    THEN check it succeeds and returns the right response
    """
    with patch("clients.factory.client_factory.get_desktop_configurations_client") as mock_client:
        # Setup mock response
        mock_config_client = MagicMock()
        mock_client.return_value = mock_config_client

        # Make request
        response = admin_client.delete("/api/configurations/1")

        # Check response
        assert response.status_code == 200
        json_data = response.get_json()
        assert json_data["success"] is True
        assert json_data["message"] == "Configuration deleted successfully"

        # Verify the call was made with the right config_id and some token
        mock_config_client.delete_configuration.assert_called_once()
        call_args, call_kwargs = mock_config_client.delete_configuration.call_args
        assert call_kwargs["config_id"] == 1
        assert "token" in call_kwargs


def test_delete_configuration_unauthorized(logged_in_client):
    """
    GIVEN a Flask application configured for testing
    WHEN a non-admin tries to delete a configuration
    THEN check access is denied (either by redirect or service unavailable response)
    """
    with patch("flask.session") as mock_session:
        # Make sure session is seen as not admin
        mock_session.get.side_effect = lambda k, *args: False if k == "is_admin" else None

        response = logged_in_client.delete("/api/configurations/1", follow_redirects=False)

        # Should either redirect to login or show service unavailable
        # Both indicate the request was not processed as expected
        assert response.status_code == 403
        assert "You need administrator privileges" in response.data.decode("utf-8")
