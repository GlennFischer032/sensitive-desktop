"""Client for API Token management.

This module provides a client for interacting with the API token management endpoints.
"""

from typing import Any, Dict, List, Optional

from .base import APIError, BaseClient, ClientRequest


class TokensClient(BaseClient):
    """Client for token-related API interactions."""

    def list_tokens(self) -> Dict[str, List[Dict[str, Any]]]:
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
        description: Optional[str] = None,
        expires_in_days: int = 30,
    ) -> Dict[str, Any]:
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

    def get_token(self, token_id: str) -> Dict[str, Any]:
        """Get details for a specific token.

        Args:
            token_id: The unique ID of the token

        Returns:
            Dict[str, Any]: Token details

        Raises:
            APIError: If request fails
        """

        try:
            request = ClientRequest(
                endpoint=f"/api/tokens/{token_id}",
                timeout=10,
            )
            data, _ = self.get(request=request)
            return data
        except APIError as e:
            self.logger.error(f"Error fetching token details: {str(e)}")
            raise

    def revoke_token(self, token_id: str) -> Dict[str, Any]:
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
