"""Client modules for desktop-manager-api.

This package provides client modules for interacting with various services:
- DatabaseClient: For database operations
- GuacamoleClient: For interacting with Apache Guacamole
- RancherClient: For managing Rancher deployments
"""

from desktop_manager.clients.factory import ClientFactory, client_factory
from desktop_manager.clients.guacamole import GuacamoleClient
from desktop_manager.clients.rancher import RancherClient


__all__ = [
    "ClientFactory",
    "DatabaseClient",
    "GuacamoleClient",
    "RancherClient",
    "client_factory",
]
