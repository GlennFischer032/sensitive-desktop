"""Users client for API interactions."""

from typing import Any

from .base import APIError, BaseClient, ClientRequest


class UsersClient(BaseClient):
    """Client for user-related API interactions."""

    def list_users(self, token: str | None = None) -> list[dict[str, Any]]:
        """Get list of users.

        Returns:
            List[Dict[str, Any]]: List of users

        Raises:
            APIError: If request fails
        """

        try:
            request = ClientRequest(
                endpoint="/api/users/list",
                timeout=10,
                token=token,
            )
            data, _ = self.get(request=request)
            return data.get("users", [])
        except APIError as e:
            self.logger.error(f"Error fetching users: {str(e)}")
            raise

    def add_user(
        self,
        username: str,
        sub: str,
        is_admin: bool = False,
        token: str | None = None,
    ) -> dict[str, Any]:
        """Add a new user.

        Args:
            username: Username
            sub: OIDC subject identifier
            is_admin: Whether the user is an admin

        Returns:
            Dict[str, Any]: Response data

        Raises:
            APIError: If request fails
        """

        # Build request data with only the required fields
        data = {
            "username": username,
            "sub": sub,
            "is_admin": is_admin,
        }

        try:
            request = ClientRequest(
                endpoint="/api/users/createuser",
                data=data,
                timeout=10,
                token=token,
            )
            data, _ = self.post(request=request)
            return data
        except APIError as e:
            self.logger.error(f"Error adding user: {str(e)}")
            raise

    def delete_user(self, username: str, token: str | None = None) -> dict[str, Any]:
        """Delete a user.

        Args:
            username: Username

        Returns:
            Dict[str, Any]: Response data

        Raises:
            APIError: If request fails
        """

        try:
            request = ClientRequest(
                endpoint="/api/users/removeuser",
                data={"username": username},
                timeout=10,
                token=token,
            )
            data, _ = self.post(request=request)
            return data
        except APIError as e:
            self.logger.error(f"Error deleting user: {str(e)}")
            raise

    def get_user(self, username: str, token: str | None = None) -> dict[str, Any]:
        """Get user details.

        Args:
            username: Username

        Returns:
            Dict[str, Any]: User details

        Raises:
            APIError: If request fails
        """

        try:
            request = ClientRequest(
                endpoint=f"/api/users/{username}",
                timeout=10,
                token=token,
            )
            data, _ = self.get(request=request)
            return data.get("user", {})
        except APIError as e:
            self.logger.error(f"Error fetching user details: {str(e)}")
            raise

    def verify_user(self, sub: str) -> tuple[dict[str, Any], int]:
        """Verify if a user exists with the provided sub ID.

        Args:
            sub: OIDC subject identifier

        Returns:
            Tuple[Dict[str, Any], int]: User data and status code

        Raises:
            APIError: If verification fails
        """
        try:
            request = ClientRequest(
                endpoint="/api/users/verify",
                params={"sub": sub},
                timeout=5,
            )
            return self.get(request=request)
        except APIError as e:
            self.logger.error(f"User verification error: {str(e)}")
            raise
