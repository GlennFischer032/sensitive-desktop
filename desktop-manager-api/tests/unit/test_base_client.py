import unittest
from unittest.mock import patch, MagicMock

from clients.base import BaseClient, APIError
import requests


class TestBaseClient(unittest.TestCase):
    """Test cases for BaseClient class."""

    def setUp(self):
        """Set up test fixtures."""
        self.base_url = "http://api.example.com"
        self.client = BaseClient(base_url=self.base_url)

    def test_get_base_url_empty(self):
        """Test _get_base_url when base_url is empty."""
        client = BaseClient(base_url=None)
        self.assertEqual(client._get_base_url(), "")

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
        self.assertTrue("HTTP error" in context.exception.message)

    @patch("clients.base.requests.request")
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

    @patch("clients.base.requests.request")
    def test_request_request_exception(self, mock_request):
        """Test _request with RequestException."""
        # Mock requests.request to raise RequestException
        mock_request.side_effect = requests.exceptions.RequestException("Network error")

        # Call the method and expect an exception
        with self.assertRaises(APIError) as context:
            self.client._request(method="GET", endpoint="/test")

        # Verify the exception details
        self.assertEqual(context.exception.status_code, 500)
        self.assertTrue("Request failed" in context.exception.message)

    @patch("clients.base.requests.request")
    def test_request_general_exception(self, mock_request):
        """Test _request with general exception."""
        # Mock requests.request to raise a general exception
        mock_request.side_effect = Exception("Unexpected error")

        # Call the method and expect an exception
        with self.assertRaises(APIError) as context:
            self.client._request(method="GET", endpoint="/test")

        # Verify the exception details
        self.assertEqual(context.exception.status_code, 500)
        self.assertTrue("Unexpected error" in context.exception.message)

    @patch("clients.base.BaseClient._request")
    def test_patch_method(self, mock_request):
        """Test patch method."""
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
