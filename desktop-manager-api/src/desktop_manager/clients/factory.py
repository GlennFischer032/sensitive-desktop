"""Client factory module for desktop-manager-api.

This module provides a factory for creating client instances.
"""

import logging
from typing import Optional

from desktop_manager.clients.database import DatabaseClient
from desktop_manager.clients.guacamole import GuacamoleClient
from desktop_manager.clients.rancher import RancherClient
from desktop_manager.config.settings import get_settings


class ClientFactory:
    """Factory for creating API clients.

    This factory provides methods for:
    - get_database_client: Get a DatabaseClient instance
    - get_guacamole_client: Get a GuacamoleClient instance
    - get_rancher_client: Get a RancherClient instance
    """

    def __init__(self):
        """Initialize ClientFactory."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.settings = get_settings()
        self._database_client: Optional[DatabaseClient] = None
        self._guacamole_client: Optional[GuacamoleClient] = None
        self._rancher_client: Optional[RancherClient] = None

    def get_database_client(self) -> DatabaseClient:
        """Get a DatabaseClient instance.

        Returns:
            DatabaseClient: DatabaseClient instance
        """
        if not self._database_client:
            self.logger.info("Creating new DatabaseClient instance")
            self._database_client = DatabaseClient(
                connection_string=self.settings.DATABASE_URL,
            )
        return self._database_client

    def get_guacamole_client(self) -> GuacamoleClient:
        """Get a GuacamoleClient instance.

        Returns:
            GuacamoleClient: GuacamoleClient instance
        """
        if not self._guacamole_client:
            self.logger.info("Creating new GuacamoleClient instance")
            self._guacamole_client = GuacamoleClient(
                api_url=self.settings.GUACAMOLE_API_URL,
                username=self.settings.GUACAMOLE_USERNAME,
                password=self.settings.GUACAMOLE_PASSWORD,
            )
        return self._guacamole_client

    def get_rancher_client(self) -> RancherClient:
        """Get a RancherClient instance.

        Returns:
            RancherClient: RancherClient instance
        """
        if not self._rancher_client:
            self.logger.info("Creating new RancherClient instance")
            self._rancher_client = RancherClient()
        return self._rancher_client


# Create a singleton instance of ClientFactory
client_factory = ClientFactory()
