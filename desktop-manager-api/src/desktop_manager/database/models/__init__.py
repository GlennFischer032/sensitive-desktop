"""Database models package.

This package contains SQLAlchemy ORM models for database entities.
"""

# Import models in order to avoid circular dependencies
from desktop_manager.database.models.connection import Connection
from desktop_manager.database.models.desktop_configuration import DesktopConfiguration, DesktopConfigurationAccess
from desktop_manager.database.models.storage_pvc import ConnectionPVCMap, StoragePVC, StoragePVCAccess
from desktop_manager.database.models.token import Token
from desktop_manager.database.models.user import PKCEState, SocialAuthAssociation, User


__all__ = [
    # User models
    "User",
    "SocialAuthAssociation",
    "PKCEState",
    # Desktop configuration models
    "DesktopConfiguration",
    "DesktopConfigurationAccess",
    # Connection model
    "Connection",
    # Storage PVC models
    "StoragePVC",
    "ConnectionPVCMap",
    "StoragePVCAccess",
    # Token model
    "Token",
]
