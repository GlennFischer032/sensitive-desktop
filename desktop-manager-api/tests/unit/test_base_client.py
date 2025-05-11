"""
Tests for the API client base class.
"""

import unittest
from unittest.mock import patch, MagicMock

from clients.base import BaseClient, APIError
import requests


class TestBaseClient(unittest.TestCase):
    """Comprehensive test cases for BaseClient class."""

    def setUp(self):
        """Set up test fixtures."""
        self.base_url = "https://api.example.com"
        self.client = BaseClient(base_url=self.base_url)

    def test_init(self):
        """Test initialization of BaseClient."""
        # Default timeout
        self.assertEqual(self.client.base_url, self.base_url)
        self.assertEqual(self.client.timeout, 10)

        # Custom timeout
        client = BaseClient(base_url=self.base_url, timeout=30)
        self.assertEqual(client.base_url, self.base_url)
        self.assertEqual(client.timeout, 30)

    def test_get_base_url_empty(self):
        """Test _get_base_url when base_url is empty."""
        client = BaseClient(base_url=None)
        self.assertEqual(client._get_base_url(), "")

    # HTTP Methods Tests
    def test_get(self):
        """Test GET request method."""
        with patch("requests.request") as mock_request:
            # Arrange
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"data": "test-data"}
            mock_response.content = b'{"data": "test-data"}'
            mock_request.return_value = mock_response

            # Act
            data, status_code = self.client.get("/test-endpoint")

            # Assert
            self.assertEqual(data, {"data": "test-data"})
            self.assertEqual(status_code, 200)
            mock_request.assert_called_once_with(
                method="GET",
                url=f"{self.base_url}/test-endpoint",
                json=None,
                params=None,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )

    def test_get_with_params(self):
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
            data, status_code = self.client.get("/test-endpoint", params=params)

            # Assert
            self.assertEqual(data, {"data": "test-data"})
            self.assertEqual(status_code, 200)
            mock_request.assert_called_once_with(
                method="GET",
                url=f"{self.base_url}/test-endpoint",
                json=None,
                params=params,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )

    def test_get_with_token(self):
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
            data, status_code = self.client.get("/test-endpoint", token=token)

            # Assert
            self.assertEqual(data, {"data": "test-data"})
            self.assertEqual(status_code, 200)
            mock_request.assert_called_once_with(
                method="GET",
                url=f"{self.base_url}/test-endpoint",
                json=None,
                params=None,
                headers={"Content-Type": "application/json", "Authorization": "Bearer test-token"},
                timeout=10,
            )

    def test_get_with_headers(self):
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
            data, status_code = self.client.get("/test-endpoint", headers=headers)

            # Assert
            self.assertEqual(data, {"data": "test-data"})
            self.assertEqual(status_code, 200)
            mock_request.assert_called_once_with(
                method="GET",
                url=f"{self.base_url}/test-endpoint",
                json=None,
                params=None,
                headers={"Content-Type": "application/json", "X-Custom-Header": "value"},
                timeout=10,
            )

    def test_post(self):
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
            result, status_code = self.client.post("/test-endpoint", data=data)

            # Assert
            self.assertEqual(result, {"id": 123, "name": "test"})
            self.assertEqual(status_code, 201)
            mock_request.assert_called_once_with(
                method="POST",
                url=f"{self.base_url}/test-endpoint",
                json=data,
                params=None,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )

    def test_put(self):
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
            result, status_code = self.client.put("/test-endpoint/123", data=data)

            # Assert
            self.assertEqual(result, {"id": 123, "name": "updated"})
            self.assertEqual(status_code, 200)
            mock_request.assert_called_once_with(
                method="PUT",
                url=f"{self.base_url}/test-endpoint/123",
                json=data,
                params=None,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )

    def test_delete(self):
        """Test DELETE request method."""
        with patch("requests.request") as mock_request:
            # Arrange
            mock_response = MagicMock()
            mock_response.status_code = 204
            mock_response.content = b""
            mock_request.return_value = mock_response

            # Act
            result, status_code = self.client.delete("/test-endpoint/123")

            # Assert
            self.assertEqual(result, {})  # Empty dict for no content
            self.assertEqual(status_code, 204)
            mock_request.assert_called_once_with(
                method="DELETE",
                url=f"{self.base_url}/test-endpoint/123",
                json=None,
                params=None,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )

    def test_patch_method(self):
        """Test PATCH request method."""
        with patch.object(BaseClient, "_request") as mock_request:
            # Setup return value
            mock_request.return_value = ({"status": "success"}, 200)

            # Call the method
            data, status_code = self.client.patch(
                endpoint="/test",
                data={"key": "value"},
                token="test-token",
                params={"param": "value"},
                timeout=30,
                headers={"Custom": "Header"},
            )

            # Verify the result and request
            self.assertEqual(data, {"status": "success"})
            self.assertEqual(status_code, 200)
            mock_request.assert_called_once_with(
                method="PATCH",
                endpoint="/test",
                data={"key": "value"},
                token="test-token",
                params={"param": "value"},
                timeout=30,
                headers={"Custom": "Header"},
            )

    # Response Handling Tests
    def test_handle_response_success(self):
        """Test handling successful response."""
        # Arrange
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": "test"}
        mock_response.content = b'{"data": "test"}'

        # Act
        result, status_code = self.client._handle_response(mock_response)

        # Assert
        self.assertEqual(result, {"data": "test"})
        self.assertEqual(status_code, 200)

    def test_handle_response_204_no_content(self):
        """Test handling 204 No Content response."""
        # Arrange
        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_response.content = b""

        # Act
        result, status_code = self.client._handle_response(mock_response)

        # Assert
        self.assertEqual(result, {})
        self.assertEqual(status_code, 204)

    def test_handle_response_json_decode_error(self):
        """Test _handle_response with JSONDecodeError."""
        # Create a mock response with invalid JSON
        mock_response = MagicMock(spec=requests.Response)
        mock_response.content = b"not a json"
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.side_effect = requests.exceptions.JSONDecodeError("Expecting value", "not a json", 0)

        # Call the method and expect an exception
        with self.assertRaises(APIError) as context:
            self.client._handle_response(mock_response)

        # Verify the exception details
        self.assertEqual(context.exception.status_code, 200)
        self.assertEqual(context.exception.message, "Invalid JSON response")

    def test_handle_response_http_error_with_json(self):
        """Test _handle_response with HTTPError and JSON error details."""
        # Create a mock response with JSON error details
        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 400
        mock_response.json.return_value = {"message": "Validation error", "details": {"field": "Invalid value"}}
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("400 Client Error")

        # Call the method and expect an exception
        with self.assertRaises(APIError) as context:
            self.client._handle_response(mock_response)

        # Verify the exception details
        self.assertEqual(context.exception.status_code, 400)
        self.assertEqual(context.exception.message, "Validation error")
        self.assertEqual(context.exception.details, {"field": "Invalid value"})

    def test_http_error_with_json_details(self):
        """Test handling of HTTP error with JSON error details."""
        # Create mock response with HTTP error
        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 422
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("422 Unprocessable Entity")
        # Provide JSON error details
        mock_response.json.return_value = {"message": "Validation failed", "details": {"field": ["Value is invalid"]}}

        # Call the method and expect exception
        with self.assertRaises(APIError) as context:
            self.client._handle_response(mock_response)

        # Verify the exception captures the details from JSON
        self.assertEqual(context.exception.status_code, 422)
        self.assertEqual(context.exception.message, "Validation failed")
        self.assertEqual(context.exception.details, {"field": ["Value is invalid"]})

    def test_handle_response_http_error_without_json(self):
        """Test _handle_response with HTTPError and no JSON error details."""
        # Create a mock response with non-JSON error details
        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 500
        mock_response.json.side_effect = ValueError("No JSON data")
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("500 Server Error")

        # Call the method and expect an exception
        with self.assertRaises(APIError) as context:
            self.client._handle_response(mock_response)

        # Verify the exception details
        self.assertEqual(context.exception.status_code, 500)
        self.assertIn("HTTP error", context.exception.message)

    def test_http_error_no_json(self):
        """Test handling of HTTP error without JSON error details."""
        # Create mock response with HTTP error
        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("500 Server Error")
        # JSON parsing fails
        mock_response.json.side_effect = ValueError("Not JSON")

        # Call the method and expect exception
        with self.assertRaises(APIError) as context:
            self.client._handle_response(mock_response)

        # Verify the exception contains basic error info
        self.assertEqual(context.exception.status_code, 500)
        self.assertIn("HTTP error", context.exception.message)

    # Error Handling Tests
    @patch("requests.request")
    def test_request_timeout(self, mock_request):
        """Test _request with Timeout exception."""
        # Mock requests.request to raise Timeout
        mock_request.side_effect = requests.exceptions.Timeout("Connection timed out")

        # Call the method and expect an exception
        with self.assertRaises(APIError) as context:
            self.client._request(method="GET", endpoint="/test", token="test-token")

        # Verify the exception details
        self.assertEqual(context.exception.status_code, 408)
        self.assertEqual(context.exception.message, "Request timed out")

        # Verify request was attempted with correct parameters
        mock_request.assert_called_once()
        args, kwargs = mock_request.call_args
        self.assertEqual(kwargs["method"], "GET")
        self.assertEqual(kwargs["url"], f"{self.base_url}/test")
        self.assertEqual(kwargs["timeout"], self.client.timeout)

    @patch("requests.request")
    def test_request_request_exception(self, mock_request):
        """Test _request with RequestException."""
        # Mock requests.request to raise RequestException
        mock_request.side_effect = requests.exceptions.RequestException("Network error")

        # Call the method and expect an exception
        with self.assertRaises(APIError) as context:
            self.client._request(method="GET", endpoint="/test")

        # Verify the exception details
        self.assertEqual(context.exception.status_code, 500)
        self.assertIn("Request failed", context.exception.message)

    @patch("requests.request")
    def test_request_general_exception(self, mock_request):
        """Test _request with general exception."""
        # Mock requests.request to raise a general exception
        mock_request.side_effect = Exception("Something unexpected")

        # Call the method and expect an exception
        with self.assertRaises(APIError) as context:
            self.client._request(method="POST", endpoint="/test", data={"key": "value"})

        # Verify the exception details
        self.assertEqual(context.exception.status_code, 500)
        self.assertIn("Unexpected error", context.exception.message)

        # Verify request was attempted
        mock_request.assert_called_once()

    def test_get_error_response(self):
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
            with self.assertRaises(APIError) as context:
                self.client.get("/test-endpoint")

            self.assertIn("Resource not found", str(context.exception))

    def test_get_connection_error(self):
        """Test GET request with connection error."""
        with patch("requests.request") as mock_request:
            # Arrange
            mock_request.side_effect = requests.exceptions.ConnectionError("Connection refused")

            # Act & Assert
            with self.assertRaises(APIError) as context:
                self.client.get("/test-endpoint")

            self.assertIn("Request failed", str(context.exception))
            self.assertIn("Connection refused", str(context.exception))


if __name__ == "__main__":
    unittest.main()
