"""Client factory for API clients."""

from typing import Any, Dict, Optional

from flask import Flask, current_app

from .auth import AuthClient
from .connections import ConnectionsClient
from .desktop_configurations import DesktopConfigurationsClient
from .redis_client import RedisClient
from .storage import StorageClient
from .tokens import TokensClient
from .users import UsersClient


class ClientFactory:
    """Factory for creating API clients."""

    def __init__(self):
        """Initialize factory with empty client cache."""
        self._clients: Dict[str, Any] = {}

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

    def get_redis_client(self, app: Optional[Flask] = None) -> RedisClient:
        """Get RedisClient.

        Args:
            app: Optional Flask app instance. If provided, uses app.config instead of current_app.

        Returns:
            RedisClient: Redis client
        """
        if "redis" not in self._clients:
            redis_url = None
            if app is not None:
                redis_url = app.config.get("SESSION_REDIS")
            else:
                try:
                    redis_url = current_app.config.get("SESSION_REDIS")
                except RuntimeError:
                    pass

            self._clients["redis"] = RedisClient(redis_url=redis_url)
        return self._clients["redis"]


# Factory instance
client_factory = ClientFactory()
