"""Guacamole client module for desktop-manager-api.

This module provides a client for interacting with Apache Guacamole.
"""

import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional, TypedDict, Union

import requests

from desktop_manager.clients.base import APIError, BaseClient
from desktop_manager.config.settings import get_settings


if TYPE_CHECKING:
    from desktop_manager.core.guacamole import (
        GuacamoleConnectionParameters,
        GuacamoleUser,
        GuacamoleUserAttributes,
    )


class GuacamoleClient(BaseClient):
    """Client for interacting with Apache Guacamole.

    This client provides methods for:
    - Authentication
    - User management
    - Connection management
    - Group management
    - Permission management
    """

    def __init__(
        self,
        guacamole_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        data_source: str = "postgresql",
    ):
        """Initialize GuacamoleClient.

        Args:
            guacamole_url: Guacamole base URL
            username: Guacamole admin username
            password: Guacamole admin password
            data_source: Guacamole data source
        """
        settings = get_settings()
        self.guacamole_url = guacamole_url or settings.GUACAMOLE_URL
        self.username = username or settings.GUACAMOLE_USERNAME
        self.password = password or settings.GUACAMOLE_PASSWORD
        self.data_source = data_source
        # Ensure the base URL doesn't end with a slash
        base_url = self.guacamole_url.rstrip("/")
        super().__init__(base_url=base_url)
        self.logger = logging.getLogger(self.__class__.__name__)

    def login(self) -> str:
        """Login to Guacamole and get an auth token.

        Returns:
            str: Authentication token

        Raises:
            APIError: If login fails
        """
        try:
            # Debug logging
            self.logger.info("Guacamole URL: %s", self.guacamole_url)
            self.logger.info("Guacamole username: %s", self.username)

            # Construct the tokens URL
            tokens_url = f"{self.guacamole_url}/api/tokens"
            self.logger.info("Tokens URL: %s", tokens_url)

            headers = {"Content-Type": "application/x-www-form-urlencoded"}

            try:
                response = requests.post(
                    url=tokens_url,
                    data={
                        "username": self.username,
                        "password": self.password,
                    },
                    headers=headers,
                    timeout=self.timeout,
                )
                self.logger.info("Login response status: %s", response.status_code)
                response.raise_for_status()
                data = response.json()
                self.logger.info("Successfully logged in to Guacamole")
                return data.get("authToken")
            except requests.exceptions.RequestException as e:
                self.logger.error("Request error during login: %s", str(e))
                raise APIError(f"Failed to login to Guacamole: {e!s}", status_code=401)
        except Exception as e:
            self.logger.error("Failed to login to Guacamole: %s", str(e))
            raise APIError(f"Failed to login to Guacamole: {e!s}", status_code=401)

    def create_user(
        self,
        token: str,
        username: str,
        password: str,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Create a user in Guacamole.

        Args:
            token: Authentication token
            username: Username
            password: Password
            attributes: User attributes

        Raises:
            APIError: If user creation fails
        """
        try:
            user_data: GuacamoleUser = {
                "username": username,
                "password": password,
                "attributes": attributes or {},
            }

            endpoint = f"/api/session/data/{self.data_source}/users?token={token}"
            self.post(endpoint=endpoint, data=user_data)
            self.logger.info("Created user %s in Guacamole", username)
        except APIError as e:
            self.logger.error("Failed to create user in Guacamole: %s", str(e))
            raise APIError(f"Failed to create user in Guacamole: {e!s}", status_code=e.status_code)

    def delete_user(self, token: str, username: str) -> None:
        """Delete a user from Guacamole.

        Args:
            token: Authentication token
            username: Username

        Raises:
            APIError: If user deletion fails
        """
        try:
            endpoint = f"/api/session/data/{self.data_source}/users/{username}?token={token}"
            self.delete(endpoint=endpoint)
            self.logger.info("Deleted user %s from Guacamole", username)
        except APIError as e:
            self.logger.error("Failed to delete user from Guacamole: %s", str(e))
            raise APIError(
                f"Failed to delete user from Guacamole: {e!s}", status_code=e.status_code
            )

    def get_users(self, token: str) -> Dict[str, Any]:
        """Get all users from Guacamole.

        Args:
            token: Authentication token

        Returns:
            Dict[str, Any]: Users

        Raises:
            APIError: If getting users fails
        """
        try:
            endpoint = f"/api/session/data/{self.data_source}/users?token={token}"
            data, _ = self.get(endpoint=endpoint)
            return data
        except APIError as e:
            self.logger.error("Failed to get users from Guacamole: %s", str(e))
            raise APIError(f"Failed to get users from Guacamole: {e!s}", status_code=e.status_code)

    def ensure_group(self, token: str, group_name: str) -> None:
        """Ensure a group exists in Guacamole.

        Args:
            token: Authentication token
            group_name: Group name

        Raises:
            APIError: If group creation fails
        """
        try:
            # Check if group exists
            endpoint = f"/api/session/data/{self.data_source}/userGroups?token={token}"
            data, _ = self.get(endpoint=endpoint)

            if group_name not in data:
                # Create group
                group_data = {
                    "identifier": group_name,
                    "attributes": {},
                }
                self.post(endpoint=endpoint, data=group_data)
                self.logger.info("Created group %s in Guacamole", group_name)
            else:
                self.logger.info("Group %s already exists in Guacamole", group_name)
        except APIError as e:
            self.logger.error("Failed to ensure group in Guacamole: %s", str(e))
            raise APIError(f"Failed to ensure group in Guacamole: {e!s}", status_code=e.status_code)

    def add_user_to_group(self, token: str, username: str, group_name: str) -> None:
        """Add a user to a group in Guacamole.

        Args:
            token: Authentication token
            username: Username
            group_name: Group name

        Raises:
            APIError: If adding user to group fails
        """
        try:
            # Ensure group exists
            self.ensure_group(token, group_name)

            # Add user to group
            endpoint = f"/api/session/data/{self.data_source}/userGroups/{group_name}/memberUsers?token={token}"
            patch_data = [
                {
                    "op": "add",
                    "path": "/",
                    "value": username,
                }
            ]
            self.patch(endpoint=endpoint, data=patch_data)
            self.logger.info("Added user %s to group %s in Guacamole", username, group_name)
        except APIError as e:
            self.logger.error("Failed to add user to group in Guacamole: %s", str(e))
            raise APIError(
                f"Failed to add user to group in Guacamole: {e!s}", status_code=e.status_code
            )

    def remove_user_from_group(self, token: str, username: str, group_name: str) -> None:
        """Remove a user from a group in Guacamole.

        Args:
            token: Authentication token
            username: Username
            group_name: Group name

        Raises:
            APIError: If removing user from group fails
        """
        try:
            endpoint = f"/api/session/data/{self.data_source}/userGroups/{group_name}/memberUsers/{username}?token={token}"
            self.delete(endpoint=endpoint)
            self.logger.info("Removed user %s from group %s in Guacamole", username, group_name)
        except APIError as e:
            self.logger.error("Failed to remove user from group in Guacamole: %s", str(e))
            raise APIError(
                f"Failed to remove user from group in Guacamole: {e!s}", status_code=e.status_code
            )

    def create_connection(
        self,
        token: str,
        connection_name: str,
        ip_address: str,
        password: str,
        parameters: Optional[Dict[str, str]] = None,
    ) -> str:
        """Create a VNC connection in Guacamole.

        Args:
            token: Authentication token
            connection_name: Connection name
            ip_address: IP address
            password: VNC password
            parameters: Additional connection parameters

        Returns:
            str: Connection ID

        Raises:
            APIError: If connection creation fails
        """
        try:
            # Set up connection parameters
            conn_params: GuacamoleConnectionParameters = {
                "hostname": ip_address,
                "port": "5900",
                "password": password,
                "enable_audio": "true",
            }

            # Add additional parameters if provided
            if parameters:
                conn_params.update(parameters)

            # Create connection
            connection_data = {
                "name": connection_name,
                "parentIdentifier": "ROOT",
                "protocol": "vnc",
                "parameters": conn_params,
                "attributes": {
                    "max_connections": "1",
                    "max_connections_per_user": "1",
                },
            }

            endpoint = f"/api/session/data/{self.data_source}/connections?token={token}"
            data, _ = self.post(endpoint=endpoint, data=connection_data)

            connection_id = data.get("identifier")
            self.logger.info(
                "Created connection %s in Guacamole with ID %s", connection_name, connection_id
            )
            return connection_id
        except APIError as e:
            self.logger.error("Failed to create connection in Guacamole: %s", str(e))
            raise APIError(
                f"Failed to create connection in Guacamole: {e!s}", status_code=e.status_code
            )

    def delete_connection(self, token: str, connection_id: str) -> None:
        """Delete a connection from Guacamole.

        Args:
            token: Authentication token
            connection_id: Connection ID

        Raises:
            APIError: If connection deletion fails
        """
        try:
            endpoint = (
                f"/api/session/data/{self.data_source}/connections/{connection_id}?token={token}"
            )
            self.delete(endpoint=endpoint)
            self.logger.info("Deleted connection %s from Guacamole", connection_id)
        except APIError as e:
            self.logger.error("Failed to delete connection from Guacamole: %s", str(e))
            raise APIError(
                f"Failed to delete connection from Guacamole: {e!s}", status_code=e.status_code
            )

    def grant_permission(
        self,
        token: str,
        username: str,
        connection_id: str,
        permission: str = "READ",
    ) -> None:
        """Grant permission to a user for a connection in Guacamole.

        Args:
            token: Authentication token
            username: Username
            connection_id: Connection ID
            permission: Permission type (READ, UPDATE, DELETE, ADMINISTER)

        Raises:
            APIError: If granting permission fails
        """
        try:
            endpoint = (
                f"/api/session/data/{self.data_source}/users/{username}/permissions?token={token}"
            )
            patch_data = [
                {
                    "op": "add",
                    "path": f"/connectionPermissions/{connection_id}",
                    "value": permission,
                }
            ]
            self.patch(endpoint=endpoint, data=patch_data)
            self.logger.info(
                "Granted %s permission to user %s for connection %s in Guacamole",
                permission,
                username,
                connection_id,
            )
        except APIError as e:
            self.logger.error("Failed to grant permission in Guacamole: %s", str(e))
            raise APIError(
                f"Failed to grant permission in Guacamole: {e!s}", status_code=e.status_code
            )

    def grant_group_permission(
        self,
        token: str,
        group_name: str,
        connection_id: str,
        permission: str = "READ",
    ) -> None:
        """Grant permission to a group for a connection in Guacamole.

        Args:
            token: Authentication token
            group_name: Group name
            connection_id: Connection ID
            permission: Permission type (READ, UPDATE, DELETE, ADMINISTER)

        Raises:
            APIError: If granting permission fails
        """
        try:
            endpoint = f"/api/session/data/{self.data_source}/userGroups/{group_name}/permissions?token={token}"
            patch_data = [
                {
                    "op": "add",
                    "path": f"/connectionPermissions/{connection_id}",
                    "value": permission,
                }
            ]
            self.patch(endpoint=endpoint, data=patch_data)
            self.logger.info(
                "Granted %s permission to group %s for connection %s in Guacamole",
                permission,
                group_name,
                connection_id,
            )
        except APIError as e:
            self.logger.error("Failed to grant group permission in Guacamole: %s", str(e))
            raise APIError(
                f"Failed to grant group permission in Guacamole: {e!s}", status_code=e.status_code
            )

    def update_user(
        self,
        token: str,
        username: str,
        attributes: Dict[str, Any],
    ) -> None:
        """Update a user's attributes in Guacamole.

        Args:
            token: Authentication token
            username: Username to update
            attributes: Dictionary of user attributes to update

        Raises:
            APIError: If user update fails
        """
        try:
            endpoint = f"/api/session/data/{self.data_source}/users/{username}?token={token}"
            patch_data = [
                {
                    "op": "add",
                    "path": "/attributes",
                    "value": attributes,
                }
            ]
            self.patch(endpoint=endpoint, data=patch_data)
            self.logger.info("Updated user %s in Guacamole", username)
        except APIError as e:
            self.logger.error("Failed to update user in Guacamole: %s", str(e))
            raise APIError(f"Failed to update user in Guacamole: {e!s}", status_code=e.status_code)

    def get_user_permissions(
        self,
        token: str,
        username: str,
    ) -> Dict[str, Any]:
        """Get a user's permissions in Guacamole.

        Args:
            token: Authentication token
            username: Username

        Returns:
            Dict[str, Any]: Dictionary of user permissions

        Raises:
            APIError: If getting permissions fails
        """
        try:
            endpoint = (
                f"/api/session/data/{self.data_source}/users/{username}/permissions?token={token}"
            )
            data, _ = self.get(endpoint=endpoint)
            self.logger.info("Retrieved permissions for user %s from Guacamole", username)
            return data
        except APIError as e:
            self.logger.error("Failed to get user permissions from Guacamole: %s", str(e))
            raise APIError(
                f"Failed to get user permissions from Guacamole: {e!s}", status_code=e.status_code
            )

    def copy_user_permissions(
        self,
        token: str,
        source_username: str,
        target_username: str,
    ) -> None:
        """Copy permissions from one user to another in Guacamole.

        Args:
            token: Authentication token
            source_username: Username to copy permissions from
            target_username: Username to copy permissions to

        Raises:
            APIError: If copying permissions fails
        """
        try:
            # Get source user's permissions
            permissions = self.get_user_permissions(token, source_username)

            # Extract connection permissions
            connection_permissions = permissions.get("connectionPermissions", {})

            # Apply each connection permission to the target user
            for connection_id, permission in connection_permissions.items():
                try:
                    self.grant_permission(token, target_username, connection_id, permission)
                    self.logger.info(
                        "Copied %s permission for connection %s from user %s to user %s",
                        permission,
                        connection_id,
                        source_username,
                        target_username,
                    )
                except APIError as e:
                    self.logger.error(
                        "Failed to copy permission for connection %s: %s", connection_id, str(e)
                    )

            # Log completion
            self.logger.info(
                "Copied all available permissions from user %s to user %s",
                source_username,
                target_username,
            )
        except APIError as e:
            self.logger.error("Failed to copy user permissions in Guacamole: %s", str(e))
            raise APIError(
                f"Failed to copy user permissions in Guacamole: {e!s}", status_code=e.status_code
            )

    def create_user_if_not_exists(
        self,
        token: str,
        username: str,
        password: str,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Create a user in Guacamole if they don't already exist.

        Args:
            token: Authentication token
            username: Username to create
            password: Password for the user
            attributes: User attributes

        Raises:
            APIError: If user creation fails
        """
        try:
            # First try to get all users and check if the user exists
            try:
                users_endpoint = f"/api/session/data/{self.data_source}/users?token={token}"
                users_data, _ = self.get(endpoint=users_endpoint)

                # Check if the user exists in the list of users
                if username in users_data:
                    self.logger.info("User %s already exists in Guacamole", username)
                    return

                # If we get here, the user doesn't exist, so create them
                self.create_user(token, username, password, attributes)
            except APIError as e:
                # If we can't get the list of users, try to create the user directly
                if e.status_code == 404:
                    self.logger.warning(
                        "Could not check if user exists, attempting to create: %s", str(e)
                    )
                    self.create_user(token, username, password, attributes)
                else:
                    raise
        except APIError as e:
            self.logger.error("Failed to check/create user in Guacamole: %s", str(e))
            raise APIError(
                f"Failed to check/create user in Guacamole: {e!s}", status_code=e.status_code
            )


# Helper functions for backward compatibility


def guacamole_login() -> str:
    """Backward compatibility function for guacamole login."""
    client = GuacamoleClient()
    return client.login()


def create_guacamole_user(
    token: str,
    username: str,
    password: str,
    attributes: Optional[Dict[str, Any]] = None,
) -> None:
    """Backward compatibility function for creating a user."""
    client = GuacamoleClient()
    client.create_user(token, username, password, attributes)


def delete_guacamole_user(token: str, username: str) -> None:
    """Backward compatibility function for deleting a user."""
    client = GuacamoleClient()
    client.delete_user(token, username)


def ensure_all_users_group(token: str) -> None:
    """Backward compatibility function for ensuring all_users group."""
    client = GuacamoleClient()
    client.ensure_group(token, "all_users")


def ensure_admins_group(token: str) -> None:
    """Backward compatibility function for ensuring admins group."""
    client = GuacamoleClient()
    client.ensure_group(token, "admins")


def add_user_to_group(token: str, username: str, group_name: str) -> None:
    """Backward compatibility function for adding user to group."""
    client = GuacamoleClient()
    client.add_user_to_group(token, username, group_name)


def remove_user_from_group(token: str, username: str, group_name: str) -> None:
    """Backward compatibility function for removing user from group."""
    client = GuacamoleClient()
    client.remove_user_from_group(token, username, group_name)


def update_guacamole_user(token: str, username: str, attributes: Dict[str, Any]) -> None:
    """Backward compatibility function for updating a user."""
    client = GuacamoleClient()
    client.update_user(token, username, attributes)


def grant_group_permission_on_connection(
    token: str, group_name: str, connection_id: str, data_source: str = "postgresql"
) -> None:
    """Backward compatibility function for granting group permission on connection."""
    client = GuacamoleClient(data_source=data_source)
    client.grant_group_permission(token, group_name, connection_id)


def delete_guacamole_connection(
    token: str, connection_id: str, data_source: str = "postgresql"
) -> None:
    """Backward compatibility function for deleting a connection."""
    client = GuacamoleClient(data_source=data_source)
    client.delete_connection(token, connection_id)


def create_guacamole_user_if_not_exists(
    token: str, username: str, password: str, data_source: str = "postgresql"
) -> None:
    """Backward compatibility function for creating a user if not exists."""
    client = GuacamoleClient(data_source=data_source)
    client.create_user_if_not_exists(token, username, password)


def grant_user_permission_on_connection(
    token: str, username: str, connection_id: str, data_source: str = "postgresql"
) -> None:
    """Backward compatibility function for granting user permission on connection."""
    client = GuacamoleClient(data_source=data_source)
    client.grant_permission(token, username, connection_id)


def create_guacamole_connection(
    token: str,
    connection_name: str,
    ip_address: str,
    password: str,
    data_source: str = "postgresql",
) -> str:
    """Backward compatibility function for creating a connection."""
    client = GuacamoleClient(data_source=data_source)
    return client.create_connection(token, connection_name, ip_address, password)


def copy_user_permissions(
    token: str,
    source_username: str,
    target_username: str,
    data_source: str = "postgresql",
) -> None:
    """Backward compatibility function for copying user permissions.

    Args:
        token: Authentication token
        source_username: Username to copy permissions from
        target_username: Username to copy permissions to
        data_source: Guacamole data source
    """
    client = GuacamoleClient(data_source=data_source)
    client.copy_user_permissions(token, source_username, target_username)
