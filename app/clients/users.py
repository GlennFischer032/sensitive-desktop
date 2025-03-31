"""Users client for API interactions."""

from typing import Any, Dict, List, Optional, Tuple

from flask import session

from .base import APIError, BaseClient


class UsersClient(BaseClient):
    """Client for user-related API interactions."""

    def list_users(self, token: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get list of users.

        Args:
            token: Authentication token. If None, uses token from session.

        Returns:
            List[Dict[str, Any]]: List of users

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            self.logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        try:
            data, _ = self.get(
                endpoint="/api/users/list",
                token=token,
                timeout=10,
            )
            return data.get("users", [])
        except APIError as e:
            self.logger.error(f"Error fetching users: {str(e)}")
            raise

    def add_user(
        self,
        username: str,
        sub: str,
        is_admin: bool = False,
        token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Add a new user.

        Args:
            username: Username
            sub: OIDC subject identifier
            is_admin: Whether the user is an admin
            token: Authentication token. If None, uses token from session.

        Returns:
            Dict[str, Any]: Response data

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            self.logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        # Build request data with only the required fields
        data = {
            "username": username,
            "sub": sub,
            "is_admin": is_admin,
        }

        try:
            data, _ = self.post(
                endpoint="/api/users/createuser",
                data=data,
                token=token,
                timeout=10,
            )
            return data
        except APIError as e:
            self.logger.error(f"Error adding user: {str(e)}")
            raise

    def delete_user(self, username: str, token: Optional[str] = None) -> Dict[str, Any]:
        """Delete a user.

        Args:
            username: Username
            token: Authentication token. If None, uses token from session.

        Returns:
            Dict[str, Any]: Response data

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            self.logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        try:
            data, _ = self.post(
                endpoint="/api/users/removeuser",
                data={"username": username},
                token=token,
                timeout=10,
            )
            return data
        except APIError as e:
            self.logger.error(f"Error deleting user: {str(e)}")
            raise

    def get_user(self, username: str, token: Optional[str] = None) -> Dict[str, Any]:
        """Get user details.

        Args:
            username: Username
            token: Authentication token. If None, uses token from session.

        Returns:
            Dict[str, Any]: User details

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            self.logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        try:
            data, _ = self.get(
                endpoint=f"/api/users/{username}",
                token=token,
                timeout=10,
            )
            return data.get("user", {})
        except APIError as e:
            self.logger.error(f"Error fetching user details: {str(e)}")
            raise

    def update_user(
        self,
        username: str,
        organization: Optional[str] = None,
        is_admin: Optional[bool] = None,
        locale: Optional[str] = None,
        token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update a user's information.

        Args:
            username: Username of the user to update
            organization: User's organization
            is_admin: Whether the user is an admin
            locale: User's locale preference
            token: Authentication token. If None, uses token from session.

        Returns:
            Dict[str, Any]: Response data

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            self.logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        # Build request data with only provided fields
        data = {}
        if organization is not None:
            data["organization"] = organization
        if is_admin is not None:
            data["is_admin"] = is_admin
        if locale is not None:
            data["locale"] = locale

        if not data:
            self.logger.error("No update fields provided")
            raise APIError("No update fields provided", status_code=400)

        try:
            data, _ = self.post(
                endpoint=f"/api/users/update/{username}",
                data=data,
                token=token,
                timeout=10,
            )
            return data
        except APIError as e:
            self.logger.error(f"Error updating user: {str(e)}")
            raise
