import unittest
from unittest.mock import patch, MagicMock

from clients.base import BaseClient, APIError
import requests


class TestBaseClientAdditional(unittest.TestCase):
    """Additional test cases for BaseClient class to improve coverage."""

    def setUp(self):
        """Set up test fixtures."""
        self.base_url = "http://api.example.com"
        self.client = BaseClient(base_url=self.base_url)

    def test_empty_base_url(self):
        """Test behavior with empty base URL."""
        client = BaseClient(base_url=None)
        self.assertEqual(client._get_base_url(), "")

    def test_request_timeout(self):
        """Test request method with timeout exception."""
        with patch("requests.request") as mock_request:
            # Setup mock to raise Timeout
            mock_request.side_effect = requests.exceptions.Timeout("Connection timed out")

            # Call method and expect exception
            with self.assertRaises(APIError) as context:
                self.client._request(method="GET", endpoint="/test")

            # Verify exception details
            self.assertEqual(context.exception.status_code, 408)
            self.assertEqual(context.exception.message, "Request timed out")

            # Verify request was attempted with correct parameters
            mock_request.assert_called_once()
            args, kwargs = mock_request.call_args
            self.assertEqual(kwargs["method"], "GET")
            self.assertEqual(kwargs["url"], f"{self.base_url}/test")
            self.assertEqual(kwargs["timeout"], self.client.timeout)

    def test_request_general_exception(self):
        """Test request method with general exception."""
        with patch("requests.request") as mock_request:
            # Setup mock to raise a general exception
            mock_request.side_effect = Exception("Something unexpected")

            # Call method and expect exception
            with self.assertRaises(APIError) as context:
                self.client._request(method="POST", endpoint="/test", data={"key": "value"})

            # Verify exception details
            self.assertEqual(context.exception.status_code, 500)
            self.assertIn("Unexpected error", context.exception.message)

            # Verify request was attempted
            mock_request.assert_called_once()

    def test_patch_method(self):
        """Test the patch method."""
        with patch.object(BaseClient, "_request") as mock_request:
            # Setup return value
            mock_request.return_value = ({"result": "success"}, 200)

            # Call the patch method
            data, status = self.client.patch(
                endpoint="/update",
                data={"key": "value"},
                token="test-token",
                params={"param": "value"},
                timeout=30,
                headers={"X-Custom": "value"},
            )

            # Verify results
            self.assertEqual(data, {"result": "success"})
            self.assertEqual(status, 200)

            # Verify _request was called with correct parameters
            mock_request.assert_called_once_with(
                method="PATCH",
                endpoint="/update",
                data={"key": "value"},
                token="test-token",
                params={"param": "value"},
                timeout=30,
                headers={"X-Custom": "value"},
            )

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
