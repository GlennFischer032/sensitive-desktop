"""Client factory for API clients."""

from typing import Any, Dict

from flask import current_app

from .auth import AuthClient
from .base import BaseClient
from .connections import ConnectionsClient
from .desktop_configurations import DesktopConfigurationsClient
from .storage import StorageClient
from .tokens import TokensClient
from .users import UsersClient


class ClientFactory:
    """Factory for creating API clients."""

    def __init__(self):
        """Initialize factory with empty client cache."""
        self._clients: Dict[str, Any] = {}

    def get_base_client(self) -> BaseClient:
        """Get BaseClient.

        Returns:
            BaseClient: Base client
        """
        if "base" not in self._clients:
            self._clients["base"] = BaseClient(
                base_url=current_app.config["API_URL"],
            )
        return self._clients["base"]

    def get_auth_client(self) -> AuthClient:
        """Get AuthClient.

        Returns:
            AuthClient: Auth client
        """
        if "auth" not in self._clients:
            self._clients["auth"] = AuthClient(
                base_url=current_app.config["API_URL"],
            )
        return self._clients["auth"]

    def get_connections_client(self) -> ConnectionsClient:
        """Get ConnectionsClient.

        Returns:
            ConnectionsClient: Connections client
        """
        if "connections" not in self._clients:
            self._clients["connections"] = ConnectionsClient(
                base_url=current_app.config["API_URL"],
            )
        return self._clients["connections"]

    def get_users_client(self) -> UsersClient:
        """Get UsersClient.

        Returns:
            UsersClient: Users client
        """
        if "users" not in self._clients:
            self._clients["users"] = UsersClient(
                base_url=current_app.config["API_URL"],
            )
        return self._clients["users"]

    def get_desktop_configurations_client(self) -> DesktopConfigurationsClient:
        """Get DesktopConfigurationsClient.

        Returns:
            DesktopConfigurationsClient: Desktop configurations client
        """
        if "desktop_configurations" not in self._clients:
            self._clients["desktop_configurations"] = DesktopConfigurationsClient(
                base_url=current_app.config["API_URL"],
            )
        return self._clients["desktop_configurations"]

    def get_storage_client(self) -> StorageClient:
        """Get StorageClient.

        Returns:
            StorageClient: Storage client
        """
        if "storage" not in self._clients:
            self._clients["storage"] = StorageClient(
                base_url=current_app.config["API_URL"],
            )
        return self._clients["storage"]

    def get_connection_client(self) -> ConnectionsClient:
        """Get ConnectionClient.

        Returns:
            ConnectionClient: Connection client
        """
        return ConnectionsClient(current_app.config["API_URL"], current_app.config["AUTH_TOKEN"])

    def get_user_client(self) -> UsersClient:
        """Get UserClient.

        Returns:
            UserClient: User client
        """
        return UsersClient(current_app.config["API_URL"], current_app.config["AUTH_TOKEN"])

    def get_desktop_configuration_client(self) -> DesktopConfigurationsClient:
        """Get DesktopConfigurationClient.

        Returns:
            DesktopConfigurationClient: Desktop configuration client
        """
        return DesktopConfigurationsClient(current_app.config["API_URL"], current_app.config["AUTH_TOKEN"])

    def get_storage_pvc_client(self) -> StorageClient:
        """Get StoragePVCClient.

        Returns:
            StoragePVCClient: Storage PVC client
        """
        return StorageClient(current_app.config["API_URL"], current_app.config["AUTH_TOKEN"])

    def get_tokens_client(self) -> TokensClient:
        """Get TokensClient.

        Returns:
            TokensClient: Token client
        """
        if "tokens" not in self._clients:
            self._clients["tokens"] = TokensClient(
                base_url=current_app.config["API_URL"],
            )
        return self._clients["tokens"]


# Factory instance
client_factory = ClientFactory()
