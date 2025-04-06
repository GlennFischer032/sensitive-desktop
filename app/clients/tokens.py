"""Client for API Token management.

This module provides a client for interacting with the API token management endpoints.
"""

from typing import Any, Dict, List, Optional

from flask import session

from .base import APIError, BaseClient


class TokensClient(BaseClient):
    """Client for token-related API interactions."""

    def list_tokens(self, token: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
        """Get list of API tokens.

        Args:
            token: Authentication token. If None, uses token from session.

        Returns:
            Dict[str, List[Dict[str, Any]]]: List of tokens

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            self.logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        try:
            data, _ = self.get(
                endpoint="/api/tokens",
                token=token,
                timeout=10,
            )
            return data
        except APIError as e:
            self.logger.error(f"Error fetching tokens: {str(e)}")
            raise

    def create_token(
        self,
        name: str,
        description: Optional[str] = None,
        expires_in_days: int = 30,
        token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new API token.

        Args:
            name: Name for the token
            description: Optional description for the token
            expires_in_days: Number of days until token expiration (default: 30)
            token: Authentication token. If None, uses token from session.

        Returns:
            Dict[str, Any]: Created token details including the JWT token

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            self.logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        data = {
            "name": name,
            "expires_in_days": expires_in_days,
        }

        if description:
            data["description"] = description

        try:
            data, _ = self.post(
                endpoint="/api/tokens",
                data=data,
                token=token,
                timeout=10,
            )
            return data
        except APIError as e:
            self.logger.error(f"Error creating token: {str(e)}")
            raise

    def get_token(self, token_id: str, token: Optional[str] = None) -> Dict[str, Any]:
        """Get details for a specific token.

        Args:
            token_id: The unique ID of the token
            token: Authentication token. If None, uses token from session.

        Returns:
            Dict[str, Any]: Token details

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            self.logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        try:
            data, _ = self.get(
                endpoint=f"/api/tokens/{token_id}",
                token=token,
                timeout=10,
            )
            return data
        except APIError as e:
            self.logger.error(f"Error fetching token details: {str(e)}")
            raise

    def revoke_token(self, token_id: str, token: Optional[str] = None) -> Dict[str, Any]:
        """Revoke a token.

        Args:
            token_id: The unique ID of the token to revoke
            token: Authentication token. If None, uses token from session.

        Returns:
            Dict[str, Any]: Success message

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            self.logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        try:
            data, _ = self.delete(
                endpoint=f"/api/tokens/{token_id}",
                token=token,
                timeout=10,
            )
            return data
        except APIError as e:
            self.logger.error(f"Error revoking token: {str(e)}")
            raise
