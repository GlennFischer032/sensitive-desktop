"""Models package for desktop-manager-api."""

from models.base import APIModel
from models.storage_pvc import (
    ConnectionPVCMap,
    StoragePVC,
    StoragePVCBase,
    StoragePVCCreate,
    StoragePVCUpdate,
)

# Import schemas separately if needed
from schemas.connection import (
    ConnectionBase,
    ConnectionCreate,
    ConnectionUpdate,
)
from schemas.desktop_configuration import (
    DesktopConfigurationBase,
    DesktopConfigurationCreate,
    DesktopConfigurationUpdate,
)
from schemas.user import UserBase, UserCreate


__all__ = [
    "APIModel",
    "Connection",
    "ConnectionBase",
    "ConnectionCreate",
    "ConnectionPVCMap",
    "ConnectionUpdate",
    "DesktopConfiguration",
    "DesktopConfigurationAccess",
    "DesktopConfigurationBase",
    "DesktopConfigurationCreate",
    "DesktopConfigurationUpdate",
    "PKCEState",
    "SocialAuthAssociation",
    "StoragePVC",
    "StoragePVCBase",
    "StoragePVCCreate",
    "StoragePVCUpdate",
    "User",
    "UserBase",
    "UserCreate",
]
