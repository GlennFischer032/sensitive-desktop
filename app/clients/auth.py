"""Authentication client for API interactions."""

from typing import Any, Dict, Optional, Tuple

from flask import session

from .base import APIError, BaseClient


class AuthClient(BaseClient):
    """Client for authentication-related API interactions."""

    def login(self, username: str, password: str) -> Tuple[Dict[str, Any], int]:
        """Authenticate user with credentials.

        Args:
            username: Username
            password: Password

        Returns:
            Tuple[Dict[str, Any], int]: Authentication response and status code

        Raises:
            APIError: If authentication fails
        """
        try:
            data, status_code = self.post(
                endpoint="/api/auth/login",
                data={"username": username, "password": password},
                timeout=5,
            )

            # Store authentication data in session
            if status_code == 200:
                session["token"] = data["token"]
                session["username"] = data["username"]
                session["is_admin"] = data["is_admin"]
                session.permanent = True

            return data, status_code
        except APIError as e:
            self.logger.error(f"Login error: {str(e)}")
            raise

    def logout(self) -> None:
        """Log out the current user by clearing the session."""
        # Clear session data
        session.pop("token", None)
        session.pop("username", None)
        session.pop("is_admin", None)
        session.pop("logged_in", None)

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
            return self.get(
                endpoint="/api/auth/verify",
                token=token,
                timeout=5,
            )
        except APIError as e:
            self.logger.error(f"Token validation error: {str(e)}")
            raise
