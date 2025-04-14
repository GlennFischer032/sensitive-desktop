import logging
from http import HTTPStatus
from typing import Any

import requests
from flask import session
from pydantic import ValidationError

from app.clients.factory import client_factory

logger = logging.getLogger(__name__)


class AuthError(Exception):
    """Custom exception for authentication errors."""

    def __init__(self, message: str, status_code: int = HTTPStatus.UNAUTHORIZED):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class RateLimitError(AuthError):
    """Exception for rate limit errors."""

    def __init__(self, retry_after: int):
        self.retry_after = retry_after
        super().__init__(
            f"Rate limit exceeded. Please try again in {retry_after} seconds.",
            HTTPStatus.TOO_MANY_REQUESTS,
        )


def handle_auth_response(response: requests.Response) -> tuple[dict[str, Any], int]:
    """
    Handle authentication API response.

    Args:
        response: Response from auth API

    Returns:
        Tuple[Dict[str, Any], int]: Response data and status code

    Raises:
        AuthError: If authentication fails
        RateLimitError: If rate limited
        ValidationError: If response validation fails
    """
    try:
        if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
            retry_after = int(response.headers.get("Retry-After", 60))
            raise RateLimitError(retry_after)

        data = response.json()

        if response.status_code != HTTPStatus.OK:
            raise AuthError(data.get("error", "Authentication failed"), response.status_code)

        return data, HTTPStatus.OK

    except requests.exceptions.RequestException as e:
        logger.error(f"Request error: {str(e)}")
        raise AuthError("Failed to connect to authentication service") from e
    except ValidationError as e:
        logger.error(f"Response validation error: {str(e)}")
        raise AuthError("Invalid response from authentication service") from e


def logout() -> None:
    """Clear user session."""
    session.clear()


def is_authenticated() -> bool:
    """Check if user is authenticated."""
    return session.get("logged_in", False)


def refresh_token(token: str) -> None:
    """
    Refresh authentication token.

    Raises:
        AuthError: If token refresh fails
        RateLimitError: If rate limited
    """
    try:
        auth_client = client_factory.get_auth_client(token=token)
        auth_data, status_code = auth_client.refresh_token()

        if status_code == HTTPStatus.OK:
            session["token"] = auth_data["token"]

    except requests.exceptions.RequestException as e:
        logger.error(f"Token refresh error: {str(e)}")
        # Clear session on refresh failure
        logout()
        raise AuthError("Network error") from e
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        # Clear session on refresh failure
        logout()
        raise
