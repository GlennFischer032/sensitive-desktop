"""Base client for API interactions."""

import logging
from http import HTTPStatus
from typing import Any, Dict, Optional, Tuple, Union

import requests
from flask import current_app
from requests.exceptions import ConnectionError, RequestException, Timeout

logger = logging.getLogger(__name__)


class APIError(Exception):
    """Exception raised for API errors."""

    def __init__(
        self, message: str, status_code: int = 500, details: Optional[Dict[str, Any]] = None
    ):
        """Initialize APIError.

        Args:
            message: Error message
            status_code: HTTP status code
            details: Additional error details
        """
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(self.message)


class BaseClient:
    """Base client for API interactions."""

    def __init__(self, base_url: Optional[str] = None, timeout: int = 10):
        """Initialize the base client.

        Args:
            base_url: Base URL for API requests. If None, uses API_URL from config.
            timeout: Default timeout for requests in seconds
        """
        self.base_url = base_url
        self.timeout = timeout
        self.logger = logger

    def _get_base_url(self) -> str:
        """Get the base URL for API requests.

        Returns:
            str: Base URL for API requests
        """
        if self.base_url:
            return self.base_url
        return current_app.config["API_URL"]

    def _get_headers(self, token: Optional[str] = None) -> Dict[str, str]:
        """Get headers for API requests.

        Args:
            token: Authentication token

        Returns:
            Dict[str, str]: Headers for API requests
        """
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _handle_response(self, response: requests.Response) -> Tuple[Dict[str, Any], int]:
        """Handle API response.

        Args:
            response: Response from API

        Returns:
            Tuple[Dict[str, Any], int]: Response data and status code

        Raises:
            APIError: If response status code is not successful
        """
        try:
            data = response.json() if response.content else {}
        except ValueError:
            data = {"error": "Invalid JSON response", "raw": response.text}

        if not 200 <= response.status_code < 300:
            error_message = data.get("error", "Unknown error occurred")
            self.logger.error(f"API error: {error_message}, Status: {response.status_code}")
            raise APIError(
                message=error_message,
                status_code=response.status_code,
                details=data.get("details", {}),
            )

        return data, response.status_code

    def _request(
        self,
        method: str,
        endpoint: str,
        token: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[Dict[str, Any], int]:
        """Make a request to the API.

        Args:
            method: HTTP method
            endpoint: API endpoint
            token: Authentication token
            data: Request data
            params: Query parameters
            timeout: Request timeout in seconds
            headers: Additional headers

        Returns:
            Tuple[Dict[str, Any], int]: Response data and status code

        Raises:
            APIError: If request fails
        """
        url = f"{self._get_base_url()}{endpoint}"
        request_headers = self._get_headers(token)
        if headers:
            request_headers.update(headers)

        request_timeout = timeout if timeout is not None else self.timeout

        self.logger.debug(f"Making {method} request to {url}")
        try:
            # Ensure we have the right Content-Type header
            if method.upper() in ["POST", "PUT"] and data is not None:
                request_headers["Content-Type"] = "application/json"

            response = requests.request(
                method=method,
                url=url,
                json=data,
                params=params,
                headers=request_headers,
                timeout=request_timeout,
            )
            return self._handle_response(response)
        except Timeout:
            self.logger.error(f"Request to {url} timed out after {request_timeout}s")
            raise APIError(
                message=f"Request timed out after {request_timeout} seconds",
                status_code=HTTPStatus.GATEWAY_TIMEOUT,
            )
        except ConnectionError as e:
            self.logger.error(f"Connection error to {url}: {str(e)}")
            raise APIError(
                message=f"Connection error: {str(e)}",
                status_code=HTTPStatus.SERVICE_UNAVAILABLE,
            )
        except RequestException as e:
            self.logger.error(f"Request error to {url}: {str(e)}")
            raise APIError(
                message=f"Request error: {str(e)}",
                status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            )

    def get(
        self,
        endpoint: str,
        token: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[Dict[str, Any], int]:
        """Make a GET request to the API.

        Args:
            endpoint: API endpoint
            token: Authentication token
            params: Query parameters
            timeout: Request timeout in seconds
            headers: Additional headers

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
        data: Optional[Dict[str, Any]] = None,
        token: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[Dict[str, Any], int]:
        """Make a POST request to the API.

        Args:
            endpoint: API endpoint
            data: Request data
            token: Authentication token
            params: Query parameters
            timeout: Request timeout in seconds
            headers: Additional headers

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
        data: Optional[Dict[str, Any]] = None,
        token: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[Dict[str, Any], int]:
        """Make a PUT request to the API.

        Args:
            endpoint: API endpoint
            data: Request data
            token: Authentication token
            params: Query parameters
            timeout: Request timeout in seconds
            headers: Additional headers

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
        token: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[Dict[str, Any], int]:
        """Make a DELETE request to the API.

        Args:
            endpoint: API endpoint
            token: Authentication token
            data: Request data
            params: Query parameters
            timeout: Request timeout in seconds
            headers: Additional headers

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
