"""Authentication client for API interactions."""

import warnings
from typing import Any, Dict, Tuple

from flask import session

from .base import APIError, BaseClient, ClientRequest


class AuthClient(BaseClient):
    """Client for authentication-related API interactions."""

    def login(self, _username: str, _password: str) -> Tuple[Dict[str, Any], int]:
        """Authenticate user with credentials.

        Note: This method is deprecated. Use OIDC authentication instead.

        Args:
            _username: Username (unused)
            _password: Password (unused)

        Returns:
            Tuple[Dict[str, Any], int]: Authentication response and status code

        Raises:
            APIError: If authentication fails
            DeprecationWarning: Always, as this method is deprecated
        """
        warnings.warn(
            "Username/password authentication has been deprecated. " "Use OIDC authentication instead.",
            DeprecationWarning,
            stacklevel=2,
        )

        raise APIError(
            message="Username/password authentication has been disabled. Please use OIDC authentication.",
            status_code=400,
            response_data={"error": "Authentication method disabled"},
        )

    def logout(self) -> None:
        """Log out the current user by clearing the session."""
        # Clear session data
        session.pop("token", None)
        session.pop("username", None)
        session.pop("is_admin", None)
        session.pop("logged_in", None)
        session.pop("email", None)
        session.pop("organization", None)
        session.pop("sub", None)

    def check_token(self, token: str) -> Tuple[Dict[str, Any], int]:
        """Check if a token is valid.

        Args:
            token: Authentication token

        Returns:
            Tuple[Dict[str, Any], int]: Token validation response and status code

        Raises:
            APIError: If token validation fails
        """
        try:
            request = ClientRequest(
                endpoint="/api/auth/verify",
                token=token,
                timeout=5,
            )
            return self.get(request=request)
        except APIError as e:
            self.logger.error(f"Token validation error: {str(e)}")
            raise
