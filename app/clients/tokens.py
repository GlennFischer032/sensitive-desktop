"""Client for API Token management.

This module provides a client for interacting with the API token management endpoints.
"""

from typing import Any

from .base import APIError, BaseClient, ClientRequest


class TokensClient(BaseClient):
    """Client for token-related API interactions."""

    def list_tokens(self) -> dict[str, list[dict[str, Any]]]:
        """Get list of API tokens.

        Returns:
            Dict[str, List[Dict[str, Any]]]: List of tokens

        Raises:
            APIError: If request fails
        """
        try:
            request = ClientRequest(
                endpoint="/api/tokens",
                timeout=10,
            )
            data, _ = self.get(request=request)
            return data
        except APIError as e:
            self.logger.error(f"Error fetching tokens: {str(e)}")
            raise

    def create_token(
        self,
        name: str,
        description: str | None = None,
        expires_in_days: int = 30,
    ) -> dict[str, Any]:
        """Create a new API token.

        Args:
            name: Name for the token
            description: Optional description for the token
            expires_in_days: Number of days until token expiration (default: 30)

        Returns:
            Dict[str, Any]: Created token details including the JWT token

        Raises:
            APIError: If request fails
        """

        data = {
            "name": name,
            "expires_in_days": expires_in_days,
        }

        if description:
            data["description"] = description

        try:
            request = ClientRequest(
                endpoint="/api/tokens",
                data=data,
                timeout=10,
            )
            data, _ = self.post(request=request)
            return data
        except APIError as e:
            self.logger.error(f"Error creating token: {str(e)}")
            raise

    def revoke_token(self, token_id: str) -> dict[str, Any]:
        """Revoke a token.

        Args:
            token_id: The unique ID of the token to revoke

        Returns:
            Dict[str, Any]: Success message

        Raises:
            APIError: If request fails
        """

        try:
            request = ClientRequest(
                endpoint=f"/api/tokens/{token_id}",
                timeout=10,
            )
            data, _ = self.delete(request=request)
            return data
        except APIError as e:
            self.logger.error(f"Error revoking token: {str(e)}")
            raise

    def api_login(self, token: str) -> tuple[dict[str, Any], int]:
        """API login endpoint.

        This endpoint allows API clients to authenticate and receive user data.
        """
        try:
            request = ClientRequest(
                endpoint="/api/tokens/api-login",
                data={"token": token},
                timeout=5,
            )
            return self.post(request=request)
        except APIError as e:
            self.logger.error(f"API login error: {str(e)}")
            raise
