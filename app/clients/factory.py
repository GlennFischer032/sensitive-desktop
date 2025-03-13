"""Client factory for API interactions."""

from typing import Optional

from flask import current_app

from .auth import AuthClient
from .connections import ConnectionsClient
from .users import UsersClient


class ClientFactory:
    """Factory for creating API clients."""

    def __init__(self, base_url: Optional[str] = None):
        """Initialize the client factory.

        Args:
            base_url: Base URL for API requests. If None, uses API_URL from config.
        """
        self.base_url = base_url

    def get_base_url(self) -> str:
        """Get the base URL for API requests.

        Returns:
            str: Base URL for API requests
        """
        if self.base_url:
            return self.base_url
        return current_app.config["API_URL"]

    def get_auth_client(self) -> AuthClient:
        """Get the authentication client.

        Returns:
            AuthClient: Authentication client
        """
        return AuthClient(base_url=self.get_base_url())

    def get_connections_client(self) -> ConnectionsClient:
        """Get the connections client.

        Returns:
            ConnectionsClient: Connections client
        """
        return ConnectionsClient(base_url=self.get_base_url())

    def get_users_client(self) -> UsersClient:
        """Get the users client.

        Returns:
            UsersClient: Users client
        """
        return UsersClient(base_url=self.get_base_url())


# Global client factory instance
client_factory = ClientFactory()
