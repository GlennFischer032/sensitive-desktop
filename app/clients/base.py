"""Base client for API interactions."""

import logging
from http import HTTPStatus
from typing import Any

import requests
from flask import current_app, session
from pydantic import BaseModel
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import RequestException, Timeout

logger = logging.getLogger(__name__)


class APIError(Exception):
    """Exception raised for API errors."""

    def __init__(self, message: str, status_code: int = 500, details: dict[str, Any] | None = None):
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


class ClientRequest(BaseModel):
    """Model for API request parameters."""

    endpoint: str
    data: dict[str, Any] | None = None
    params: dict[str, Any] | None = None
    timeout: int | None = None
    headers: dict[str, str] | None = None


class BaseClient:
    """Base client for API interactions."""

    def __init__(self, base_url: str | None = None, timeout: int = 10):
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

    def _get_headers(self, token: str | None = None) -> dict[str, str]:
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

    def _handle_response(self, response: requests.Response) -> tuple[dict[str, Any], int]:
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

        if not HTTPStatus.OK <= response.status_code < HTTPStatus.MULTIPLE_CHOICES:
            error_message = data.get("error", "Unknown error occurred")
            self.logger.error(f"API error: {error_message}, Status: {response.status_code}")
            raise APIError(
                message=error_message,
                status_code=response.status_code,
                details=data.get("details", {}),
            )

        return data, response.status_code

    def _request(self, method: str, request: ClientRequest) -> tuple[dict[str, Any], int]:
        """Make a request to the API.

        Args:
            method: HTTP method
            request: Request parameters

        Returns:
            Tuple[Dict[str, Any], int]: Response data and status code

        Raises:
            APIError: If request fails
        """

        url = f"{self._get_base_url()}{request.endpoint}"
        request_headers = self._get_headers(session.get("token"))
        if request.headers:
            request_headers.update(request.headers)

        request_timeout = request.timeout if request.timeout is not None else self.timeout

        self.logger.debug(f"Making {method} request to {url}")
        try:
            if method.upper() in ["POST", "PUT"] and request.data is not None:
                request_headers["Content-Type"] = "application/json"

            response = requests.request(
                method=method,
                url=url,
                json=request.data,
                params=request.params,
                headers=request_headers,
                timeout=request_timeout,
            )
            return self._handle_response(response)
        except Timeout as e:
            self.logger.error(f"Request to {url} timed out after {request_timeout}s")
            raise APIError(
                message=f"Request timed out after {request_timeout} seconds",
                status_code=HTTPStatus.GATEWAY_TIMEOUT,
            ) from e
        except RequestsConnectionError as e:
            self.logger.error(f"Connection error to {url}: {str(e)}")
            raise APIError(
                message=f"Connection error: {str(e)}",
                status_code=HTTPStatus.SERVICE_UNAVAILABLE,
            ) from e
        except RequestException as e:
            self.logger.error(f"Request error to {url}: {str(e)}")
            raise APIError(
                message=f"Request error: {str(e)}",
                status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            ) from e

    def get(self, request: ClientRequest) -> tuple[dict[str, Any], int]:
        """Make a GET request to the API.

        Args:
            request: Request parameters

        Returns:
            Tuple[Dict[str, Any], int]: Response data and status code
        """
        return self._request(method="GET", request=request)

    def post(self, request: ClientRequest) -> tuple[dict[str, Any], int]:
        """Make a POST request to the API.

        Args:
            request: Request parameters

        Returns:
            Tuple[Dict[str, Any], int]: Response data and status code
        """
        return self._request(method="POST", request=request)

    def put(self, request: ClientRequest) -> tuple[dict[str, Any], int]:
        """Make a PUT request to the API.

        Args:
            request: Request parameters

        Returns:
            Tuple[Dict[str, Any], int]: Response data and status code
        """
        return self._request(method="PUT", request=request)

    def delete(self, request: ClientRequest) -> tuple[dict[str, Any], int]:
        """Make a DELETE request to the API.

        Args:
            request: Request parameters

        Returns:
            Tuple[Dict[str, Any], int]: Response data and status code
        """
        return self._request(method="DELETE", request=request)
