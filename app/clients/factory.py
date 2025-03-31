"""Client factory for API clients."""

from typing import Any, Dict, Optional

from flask import current_app

from .auth import AuthClient
from .base import BaseClient
from .connections import ConnectionsClient
from .desktop_configurations import DesktopConfigurationsClient
from .storage import StorageClient
from .users import UsersClient


class ClientFactory:
    """Factory for creating API clients."""

    def __init__(self):
        """Initialize factory with empty client cache."""
        self._clients: Dict[str, Any] = {}

    def get_base_client(self) -> BaseClient:
        """Get a base client instance.

        Returns:
            BaseClient: The base client
        """
        if "base" not in self._clients:
            self._clients["base"] = BaseClient(
                base_url=current_app.config["API_URL"],
            )
        return self._clients["base"]

    def get_auth_client(self) -> AuthClient:
        """Get an auth client instance.

        Returns:
            AuthClient: The auth client
        """
        if "auth" not in self._clients:
            self._clients["auth"] = AuthClient(
                base_url=current_app.config["API_URL"],
            )
        return self._clients["auth"]

    def get_connections_client(self) -> ConnectionsClient:
        """Get a connections client instance.

        Returns:
            ConnectionsClient: The connections client
        """
        if "connections" not in self._clients:
            self._clients["connections"] = ConnectionsClient(
                base_url=current_app.config["API_URL"],
            )
        return self._clients["connections"]

    def get_users_client(self) -> UsersClient:
        """Get a users client instance.

        Returns:
            UsersClient: The users client
        """
        if "users" not in self._clients:
            self._clients["users"] = UsersClient(
                base_url=current_app.config["API_URL"],
            )
        return self._clients["users"]

    def get_desktop_configurations_client(self) -> DesktopConfigurationsClient:
        """Get a desktop configurations client instance.

        Returns:
            DesktopConfigurationsClient: The desktop configurations client
        """
        if "desktop_configurations" not in self._clients:
            self._clients["desktop_configurations"] = DesktopConfigurationsClient(
                base_url=current_app.config["API_URL"],
            )
        return self._clients["desktop_configurations"]

    def get_storage_client(self) -> StorageClient:
        """Get a storage client instance.

        Returns:
            StorageClient: The storage client
        """
        if "storage" not in self._clients:
            self._clients["storage"] = StorageClient(
                base_url=current_app.config["API_URL"],
            )
        return self._clients["storage"]


# Factory instance
client_factory = ClientFactory()
