"""Client package for API interactions."""

from .auth import AuthClient
from .base import APIError, BaseClient
from .connections import ConnectionsClient
from .factory import ClientFactory, client_factory
from .users import UsersClient

__all__ = [
    "APIError",
    "AuthClient",
    "BaseClient",
    "ClientFactory",
    "ConnectionsClient",
    "UsersClient",
    "client_factory",
]
