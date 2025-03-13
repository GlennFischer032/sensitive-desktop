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
        password: Optional[str] = None,
        is_admin: bool = False,
        email: Optional[str] = None,
        organization: Optional[str] = None,
        sub: Optional[str] = None,
        token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Add a new user.

        Args:
            username: Username
            password: Password (optional for OIDC users)
            is_admin: Whether the user is an admin
            email: User's email address
            organization: User's organization
            sub: OIDC subject identifier (optional)
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

        # Build request data
        data = {
            "username": username,
            "is_admin": is_admin,
        }

        # Add password only if provided
        if password:
            data["password"] = password

        # Add optional fields if provided
        if email:
            data["email"] = email
        if organization:
            data["organization"] = organization
        if sub:
            data["sub"] = sub

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
