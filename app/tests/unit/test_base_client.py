"""
Unit tests for the Base client.
"""

import pytest
from unittest.mock import patch, MagicMock
from requests.exceptions import Timeout, ConnectionError as RequestsConnectionError

from app.clients.base import BaseClient, ClientRequest, APIError


def test_base_client_initialization():
    """
    GIVEN a BaseClient class
    WHEN a new BaseClient is created
    THEN check the default values are set correctly
    """
    client = BaseClient()
    assert client.base_url is None
    assert client.timeout == 10
    assert client.logger is not None


def test_base_client_with_custom_values():
    """
    GIVEN a BaseClient class
    WHEN a new BaseClient is created with custom values
    THEN check the custom values are set correctly
    """
    client = BaseClient(base_url="https://example.com", timeout=30)
    assert client.base_url == "https://example.com"
    assert client.timeout == 30


def test_client_request_model():
    """
    GIVEN a ClientRequest class
    WHEN a new ClientRequest is created
    THEN check it validates correctly
    """
    # Minimal required fields
    request = ClientRequest(endpoint="/api/test")
    assert request.endpoint == "/api/test"
    assert request.data is None
    assert request.params is None
    assert request.timeout is None
    assert request.headers is None

    # All fields
    request = ClientRequest(
        endpoint="/api/test",
        data={"key": "value"},
        params={"query": "param"},
        timeout=15,
        headers={"Custom-Header": "value"},
    )
    assert request.endpoint == "/api/test"
    assert request.data == {"key": "value"}
    assert request.params == {"query": "param"}
    assert request.timeout == 15
    assert request.headers == {"Custom-Header": "value"}


def test_get_base_url_from_instance(app):
    """
    GIVEN a BaseClient with a base_url
    WHEN _get_base_url() is called
    THEN check it returns the instance base_url
    """
    client = BaseClient(base_url="https://custom-api.com")
    assert client._get_base_url() == "https://custom-api.com"


def test_get_base_url_from_config(app):
    """
    GIVEN a BaseClient without a base_url
    WHEN _get_base_url() is called
    THEN check it returns the URL from the app config
    """
    with app.app_context():
        app.config["API_URL"] = "https://config-api.com"
        client = BaseClient()
        assert client._get_base_url() == "https://config-api.com"


def test_get_headers_without_token():
    """
    GIVEN a BaseClient
    WHEN _get_headers() is called without a token
    THEN check it returns headers without Authorization
    """
    client = BaseClient()
    headers = client._get_headers()
    assert headers == {"Content-Type": "application/json"}


def test_get_headers_with_token():
    """
    GIVEN a BaseClient
    WHEN _get_headers() is called with a token
    THEN check it returns headers with Authorization
    """
    client = BaseClient()
    headers = client._get_headers(token="test-token")
    assert headers == {"Content-Type": "application/json", "Authorization": "Bearer test-token"}


def test_handle_response_success():
    """
    GIVEN a BaseClient
    WHEN _handle_response() is called with a successful response
    THEN check it returns the parsed JSON and status code
    """
    client = BaseClient()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"key": "value"}
    mock_response.content = True

    data, status_code = client._handle_response(mock_response)

    assert data == {"key": "value"}
    assert status_code == 200


def test_handle_response_error():
    """
    GIVEN a BaseClient
    WHEN _handle_response() is called with an error response
    THEN check it raises an APIError
    """
    client = BaseClient()

    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.json.return_value = {"error": "Not found"}
    mock_response.content = True

    with pytest.raises(APIError) as exc_info:
        client._handle_response(mock_response)

    assert exc_info.value.message == "Not found"
    assert exc_info.value.status_code == 404


@patch("requests.request")
def test_request_get_success(mock_request, app):
    """
    GIVEN a BaseClient
    WHEN get() is called with a valid request
    THEN check it makes the correct HTTP request and returns the response
    """
    with app.app_context():
        app.config["API_URL"] = "https://api.example.com"

        # Mock session token
        with app.test_request_context():
            from flask import session

            session["token"] = "test-token"

            # Set up mock response
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"data": "test"}
            mock_response.content = True
            mock_request.return_value = mock_response

            # Create client and request
            client = BaseClient()
            request = ClientRequest(endpoint="/test", params={"query": "value"})

            # Call get method
            data, status_code = client.get(request)

            # Verify
            mock_request.assert_called_once_with(
                method="GET",
                url="https://api.example.com/test",
                json=None,
                params={"query": "value"},
                headers={"Content-Type": "application/json", "Authorization": "Bearer test-token"},
                timeout=10,
            )

            assert data == {"data": "test"}
            assert status_code == 200


@patch("requests.request")
def test_request_post_success(mock_request, app):
    """
    GIVEN a BaseClient
    WHEN post() is called with a valid request
    THEN check it makes the correct HTTP request and returns the response
    """
    with app.app_context():
        app.config["API_URL"] = "https://api.example.com"

        # Mock session token
        with app.test_request_context():
            from flask import session

            session["token"] = "test-token"

            # Set up mock response
            mock_response = MagicMock()
            mock_response.status_code = 201
            mock_response.json.return_value = {"id": "123"}
            mock_response.content = True
            mock_request.return_value = mock_response

            # Create client and request
            client = BaseClient()
            request = ClientRequest(endpoint="/resource", data={"name": "Test Resource"}, timeout=5)

            # Call post method
            data, status_code = client.post(request)

            # Verify
            mock_request.assert_called_once_with(
                method="POST",
                url="https://api.example.com/resource",
                json={"name": "Test Resource"},
                params=None,
                headers={"Content-Type": "application/json", "Authorization": "Bearer test-token"},
                timeout=5,
            )

            assert data == {"id": "123"}
            assert status_code == 201


@patch("requests.request")
def test_request_timeout(mock_request, app):
    """
    GIVEN a BaseClient
    WHEN a request times out
    THEN check it raises an APIError with the correct message
    """
    with app.app_context():
        app.config["API_URL"] = "https://api.example.com"

        # Set up mock
        mock_request.side_effect = Timeout("Request timed out")

        # Create client and request
        client = BaseClient()
        request = ClientRequest(endpoint="/test", timeout=5)

        # Call method and verify exception
        with pytest.raises(APIError) as exc_info:
            client.get(request)

        assert "Request timed out after 5 seconds" in exc_info.value.message
        assert exc_info.value.status_code == 504


@patch("requests.request")
def test_request_connection_error(mock_request, app):
    """
    GIVEN a BaseClient
    WHEN a connection error occurs
    THEN check it raises an APIError with the correct message
    """
    with app.app_context():
        app.config["API_URL"] = "https://api.example.com"

        # Set up mock
        mock_request.side_effect = RequestsConnectionError("Connection refused")

        # Create client and request
        client = BaseClient()
        request = ClientRequest(endpoint="/test")

        # Call method and verify exception
        with pytest.raises(APIError) as exc_info:
            client.get(request)

        assert "Connection error" in exc_info.value.message
        assert exc_info.value.status_code == 503
