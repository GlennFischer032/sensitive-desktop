"""Authentication client for API interactions."""

from typing import Any

from flask import session

from .base import APIError, BaseClient, ClientRequest


class AuthClient(BaseClient):
    """Client for authentication-related API interactions."""

    def logout(self) -> None:
        """Log out the current user by clearing the session."""
        # Clear session data
        session.clear()

    def oidc_callback(self, code: str, state: str, redirect_uri: str) -> tuple[dict[str, Any], int]:
        """Handle OIDC callback by forwarding to backend.

        Args:
            code: Authorization code from OIDC provider
            state: State parameter from OIDC provider
            redirect_uri: Redirect URI used for the OIDC flow

        Returns:
            Tuple[Dict[str, Any], int]: OIDC callback response and status code

        Raises:
            APIError: If OIDC callback fails
        """
        try:
            request = ClientRequest(
                endpoint="/api/auth/oidc/callback",
                data={
                    "code": code,
                    "state": state,
                    "redirect_uri": redirect_uri,
                },
                timeout=10,
            )
            return self.post(request=request)
        except APIError as e:
            self.logger.error(f"OIDC callback error: {str(e)}")
            raise

    def oidc_login(self) -> tuple[dict[str, Any], int]:
        """Initiate OIDC login flow using backend.

        Returns:
            Tuple[Dict[str, Any], int]: OIDC login response and status code

        Raises:
            APIError: If OIDC login initiation fails
        """
        try:
            request = ClientRequest(
                endpoint="/api/auth/oidc/login",
                timeout=5,
            )
            return self.get(request=request)
        except APIError as e:
            self.logger.error(f"OIDC login initiation error: {str(e)}")
            raise

    def refresh_token(self, token: str | None = None) -> tuple[dict[str, Any], int]:
        """Refresh the current token.

        Returns:
            Tuple[Dict[str, Any], int]: Refresh token response and status code
        """
        try:
            request = ClientRequest(
                endpoint="/api/auth/refresh",
                timeout=5,
                token=token,
            )
            return self.post(request=request)
        except APIError as e:
            self.logger.error(f"Refresh token error: {str(e)}")
            raise
