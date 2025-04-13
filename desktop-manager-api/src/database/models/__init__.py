"""Database models package.

This package contains SQLAlchemy ORM models for database entities.
"""

# Import models in order to avoid circular dependencies
from database.models.connection import Connection
from database.models.desktop_configuration import DesktopConfiguration, DesktopConfigurationAccess
from database.models.storage_pvc import ConnectionPVCMap, StoragePVC, StoragePVCAccess
from database.models.token import Token
from database.models.user import PKCEState, SocialAuthAssociation, User


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
