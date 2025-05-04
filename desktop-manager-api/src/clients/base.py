"""Base client module for desktop-manager-api.

This module provides the base client class and error handling for all clients.
"""

import logging
from typing import Any

from config.settings import get_settings
import requests
from requests.exceptions import RequestException, Timeout


class APIError(Exception):
    """Exception raised for API errors.

    Attributes:
        message: Error message
        status_code: HTTP status code
        details: Additional error details
    """

    def __init__(self, message: str, status_code: int = 500, details: dict[str, Any] | None = None):
        """Initialize APIError.

        Args:
            message: Error message
            status_code: HTTP status code
            details: Additional error details
        """
        self.message = message
        self.status_code = status_code
        self.details = details
        super().__init__(self.message)


class BaseClient:
    """Base client for API interactions.

    This class provides common functionality for all clients, including:
    - HTTP request methods (GET, POST, PUT, DELETE)
    - Error handling
    - Logging
    """

    def __init__(self, base_url: str | None = None, timeout: int = 10):
        """Initialize BaseClient.

        Args:
            base_url: Base URL for API requests
            timeout: Default timeout for requests in seconds
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.base_url = base_url
        self.timeout = timeout
        self.settings = get_settings()

    def _get_base_url(self) -> str:
        """Get the base URL for API requests.

        Returns:
            str: Base URL
        """
        if self.base_url:
            return self.base_url
        return ""

    def _get_headers(self, token: str | None = None) -> dict[str, str]:
        """Get headers for API requests.

        Args:
            token: Authentication token

        Returns:
            Dict[str, str]: Headers
        """
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _handle_response(self, response: requests.Response) -> tuple[dict[str, Any], int]:
        """Handle API response.

        Args:
            response: Response object

        Returns:
            Tuple[Dict[str, Any], int]: Response data and status code

        Raises:
            APIError: If response is not successful
        """
        try:
            response.raise_for_status()
            data = response.json() if response.content else {}
            return data, response.status_code
        except requests.exceptions.JSONDecodeError as e:
            self.logger.error("Invalid JSON response, Status: %s", response.status_code)
            raise APIError("Invalid JSON response", status_code=response.status_code) from e
        except requests.exceptions.HTTPError as e:
            status_code = response.status_code
            error_message = f"HTTP error: {e}"

            try:
                error_data = response.json()
                if isinstance(error_data, dict):
                    error_message = error_data.get("message", error_message)
                    details = error_data.get("details")
                    self.logger.error(
                        "API error: %s, Status: %s, Details: %s",
                        error_message,
                        status_code,
                        details,
                    )
                    raise APIError(error_message, status_code=status_code, details=details) from e
            except (ValueError, requests.exceptions.JSONDecodeError):
                self.logger.warning("Could not parse error response as JSON")

            self.logger.error("API error: %s, Status: %s", error_message, status_code)
            raise APIError(error_message, status_code=status_code) from e

    def _request(
        self,
        method: str,
        endpoint: str,
        token: str | None = None,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        timeout: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[dict[str, Any], int]:
        """Make an API request.

        Args:
            method: HTTP method
            endpoint: API endpoint
            token: Authentication token
            data: Request data
            params: Query parameters
            timeout: Request timeout
            headers: Custom headers

        Returns:
            Tuple[Dict[str, Any], int]: Response data and status code

        Raises:
            APIError: If request fails
        """
        self.logger.debug("Requesting %s %s", method, endpoint)
        if timeout is None:
            timeout = self.timeout

        url = f"{self._get_base_url()}{endpoint}"
        request_headers = self._get_headers(token)

        if headers:
            request_headers.update(headers)

        try:
            response = requests.request(
                method=method,
                url=url,
                json=data,
                params=params,
                headers=request_headers,
                timeout=timeout,
            )
            return self._handle_response(response)
        except Timeout as e:
            self.logger.error("Request timeout: %s %s", method, url)
            raise APIError("Request timed out", status_code=408) from e
        except RequestException as e:
            self.logger.error("Request error: %s %s - %s", method, url, str(e))
            raise APIError(f"Request failed: {e!s}", status_code=500) from e
        except Exception as e:
            self.logger.error("Unexpected error: %s %s - %s", method, url, str(e))
            raise APIError(f"Unexpected error: {e!s}", status_code=500) from e

    def get(
        self,
        endpoint: str,
        token: str | None = None,
        params: dict[str, Any] | None = None,
        timeout: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[dict[str, Any], int]:
        """Make a GET request.

        Args:
            endpoint: API endpoint
            token: Authentication token
            params: Query parameters
            timeout: Request timeout
            headers: Custom headers

        Returns:
            Tuple[Dict[str, Any], int]: Response data and status code
        """
        return self._request(
            method="GET",
            endpoint=endpoint,
            token=token,
            params=params,
            timeout=timeout,
            headers=headers,
        )

    def post(
        self,
        endpoint: str,
        data: dict[str, Any] | None = None,
        token: str | None = None,
        params: dict[str, Any] | None = None,
        timeout: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[dict[str, Any], int]:
        """Make a POST request.

        Args:
            endpoint: API endpoint
            data: Request data
            token: Authentication token
            params: Query parameters
            timeout: Request timeout
            headers: Custom headers

        Returns:
            Tuple[Dict[str, Any], int]: Response data and status code
        """
        return self._request(
            method="POST",
            endpoint=endpoint,
            token=token,
            data=data,
            params=params,
            timeout=timeout,
            headers=headers,
        )

    def put(
        self,
        endpoint: str,
        data: dict[str, Any] | None = None,
        token: str | None = None,
        params: dict[str, Any] | None = None,
        timeout: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[dict[str, Any], int]:
        """Make a PUT request.

        Args:
            endpoint: API endpoint
            data: Request data
            token: Authentication token
            params: Query parameters
            timeout: Request timeout
            headers: Custom headers

        Returns:
            Tuple[Dict[str, Any], int]: Response data and status code
        """
        return self._request(
            method="PUT",
            endpoint=endpoint,
            token=token,
            data=data,
            params=params,
            timeout=timeout,
            headers=headers,
        )

    def delete(
        self,
        endpoint: str,
        token: str | None = None,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        timeout: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[dict[str, Any], int]:
        """Make a DELETE request.

        Args:
            endpoint: API endpoint
            token: Authentication token
            data: Request data
            params: Query parameters
            timeout: Request timeout
            headers: Custom headers

        Returns:
            Tuple[Dict[str, Any], int]: Response data and status code
        """
        return self._request(
            method="DELETE",
            endpoint=endpoint,
            token=token,
            data=data,
            params=params,
            timeout=timeout,
            headers=headers,
        )

    def patch(
        self,
        endpoint: str,
        data: dict[str, Any] | None = None,
        token: str | None = None,
        params: dict[str, Any] | None = None,
        timeout: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[dict[str, Any], int]:
        """Make a PATCH request.

        Args:
            endpoint: API endpoint
            data: Request data
            token: Authentication token
            params: Query parameters
            timeout: Request timeout
            headers: Custom headers

        Returns:
            Tuple[Dict[str, Any], int]: Response data and status code
        """
        return self._request(
            method="PATCH",
            endpoint=endpoint,
            token=token,
            data=data,
            params=params,
            timeout=timeout,
            headers=headers,
        )
