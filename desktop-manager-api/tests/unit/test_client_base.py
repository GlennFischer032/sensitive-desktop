"""
Tests for the API client base class.
"""

import pytest
import sys
import os
from unittest.mock import patch, MagicMock
import requests

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from clients.base import BaseClient, APIError


class TestBaseClient:
    @pytest.fixture
    def api_client(self):
        """Create a simple API client for testing."""
        client = BaseClient(base_url="https://api.example.com")
        return client

    def test_init(self):
        """Test initialization of BaseClient."""
        # Act
        client = BaseClient(base_url="https://api.example.com", timeout=30)

        # Assert
        assert client.base_url == "https://api.example.com"
        assert client.timeout == 30

    def test_init_default_values(self):
        """Test initialization with default values."""
        # Act
        client = BaseClient(base_url="https://api.example.com")

        # Assert
        assert client.base_url == "https://api.example.com"
        assert client.timeout == 10

    def test_get(self, api_client):
        """Test GET request method."""
        with patch("requests.request") as mock_request:
            # Arrange
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"data": "test-data"}
            mock_response.content = b'{"data": "test-data"}'
            mock_request.return_value = mock_response

            # Act
            data, status_code = api_client.get("/test-endpoint")

            # Assert
            assert data == {"data": "test-data"}
            assert status_code == 200
            mock_request.assert_called_once_with(
                method="GET",
                url="https://api.example.com/test-endpoint",
                json=None,
                params=None,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )

    def test_get_with_params(self, api_client):
        """Test GET request with parameters."""
        with patch("requests.request") as mock_request:
            # Arrange
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"data": "test-data"}
            mock_response.content = b'{"data": "test-data"}'
            mock_request.return_value = mock_response

            params = {"filter": "active", "sort": "name"}

            # Act
            data, status_code = api_client.get("/test-endpoint", params=params)

            # Assert
            assert data == {"data": "test-data"}
            assert status_code == 200
            mock_request.assert_called_once_with(
                method="GET",
                url="https://api.example.com/test-endpoint",
                json=None,
                params=params,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )

    def test_get_with_token(self, api_client):
        """Test GET request with token."""
        with patch("requests.request") as mock_request:
            # Arrange
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"data": "test-data"}
            mock_response.content = b'{"data": "test-data"}'
            mock_request.return_value = mock_response

            token = "test-token"

            # Act
            data, status_code = api_client.get("/test-endpoint", token=token)

            # Assert
            assert data == {"data": "test-data"}
            assert status_code == 200
            mock_request.assert_called_once_with(
                method="GET",
                url="https://api.example.com/test-endpoint",
                json=None,
                params=None,
                headers={"Content-Type": "application/json", "Authorization": "Bearer test-token"},
                timeout=10,
            )

    def test_get_with_headers(self, api_client):
        """Test GET request with headers."""
        with patch("requests.request") as mock_request:
            # Arrange
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"data": "test-data"}
            mock_response.content = b'{"data": "test-data"}'
            mock_request.return_value = mock_response

            headers = {"X-Custom-Header": "value"}

            # Act
            data, status_code = api_client.get("/test-endpoint", headers=headers)

            # Assert
            assert data == {"data": "test-data"}
            assert status_code == 200
            mock_request.assert_called_once_with(
                method="GET",
                url="https://api.example.com/test-endpoint",
                json=None,
                params=None,
                headers={"Content-Type": "application/json", "X-Custom-Header": "value"},
                timeout=10,
            )

    def test_get_error_response(self, api_client):
        """Test GET request with error response."""
        with patch("requests.request") as mock_request:
            # Arrange
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_response.json.return_value = {"message": "Resource not found"}
            mock_response.content = b'{"message": "Resource not found"}'
            mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("404 Not Found")
            mock_request.return_value = mock_response

            # Act & Assert
            with pytest.raises(APIError) as excinfo:
                api_client.get("/test-endpoint")

            assert "Resource not found" in str(excinfo.value)

    def test_get_connection_error(self, api_client):
        """Test GET request with connection error."""
        with patch("requests.request") as mock_request:
            # Arrange
            mock_request.side_effect = requests.exceptions.ConnectionError("Connection refused")

            # Act & Assert
            with pytest.raises(APIError) as excinfo:
                api_client.get("/test-endpoint")

            assert "Request failed" in str(excinfo.value)
            assert "Connection refused" in str(excinfo.value)

    def test_get_timeout_error(self, api_client):
        """Test GET request with timeout error."""
        with patch("requests.request") as mock_request:
            # Arrange
            mock_request.side_effect = requests.exceptions.Timeout("Request timed out")

            # Act & Assert
            with pytest.raises(APIError) as excinfo:
                api_client.get("/test-endpoint")

            assert "Request timed out" in str(excinfo.value)

    def test_post(self, api_client):
        """Test POST request method."""
        with patch("requests.request") as mock_request:
            # Arrange
            mock_response = MagicMock()
            mock_response.status_code = 201
            mock_response.json.return_value = {"id": 123, "name": "test"}
            mock_response.content = b'{"id": 123, "name": "test"}'
            mock_request.return_value = mock_response

            data = {"name": "test"}

            # Act
            result, status_code = api_client.post("/test-endpoint", data=data)

            # Assert
            assert result == {"id": 123, "name": "test"}
            assert status_code == 201
            mock_request.assert_called_once_with(
                method="POST",
                url="https://api.example.com/test-endpoint",
                json=data,
                params=None,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )

    def test_put(self, api_client):
        """Test PUT request method."""
        with patch("requests.request") as mock_request:
            # Arrange
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"id": 123, "name": "updated"}
            mock_response.content = b'{"id": 123, "name": "updated"}'
            mock_request.return_value = mock_response

            data = {"name": "updated"}

            # Act
            result, status_code = api_client.put("/test-endpoint/123", data=data)

            # Assert
            assert result == {"id": 123, "name": "updated"}
            assert status_code == 200
            mock_request.assert_called_once_with(
                method="PUT",
                url="https://api.example.com/test-endpoint/123",
                json=data,
                params=None,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )

    def test_delete(self, api_client):
        """Test DELETE request method."""
        with patch("requests.request") as mock_request:
            # Arrange
            mock_response = MagicMock()
            mock_response.status_code = 204
            mock_response.content = b""
            mock_request.return_value = mock_response

            # Act
            result, status_code = api_client.delete("/test-endpoint/123")

            # Assert
            assert result == {}  # Empty dict for no content
            assert status_code == 204
            mock_request.assert_called_once_with(
                method="DELETE",
                url="https://api.example.com/test-endpoint/123",
                json=None,
                params=None,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )

    def test_handle_response_success(self, api_client):
        """Test handling successful response."""
        # Arrange
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": "test"}
        mock_response.content = b'{"data": "test"}'

        # Act
        result, status_code = api_client._handle_response(mock_response)

        # Assert
        assert result == {"data": "test"}
        assert status_code == 200

    def test_handle_response_204_no_content(self, api_client):
        """Test handling 204 No Content response."""
        # Arrange
        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_response.content = b""

        # Act
        result, status_code = api_client._handle_response(mock_response)

        # Assert
        assert result == {}
        assert status_code == 204
