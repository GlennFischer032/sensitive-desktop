"""Client modules for desktop-manager-api.

This package provides client modules for interacting with various services:
- DatabaseClient: For database operations
- GuacamoleClient: For interacting with Apache Guacamole
- RancherClient: For managing Rancher deployments
"""

from clients.factory import ClientFactory, client_factory
from clients.guacamole import GuacamoleClient
from clients.rancher import RancherClient


__all__ = [
    "ClientFactory",
    "DatabaseClient",
    "GuacamoleClient",
    "RancherClient",
    "client_factory",
]
