"""Models package for desktop-manager-api."""

from desktop_manager.api.models.base import APIModel
from desktop_manager.api.models.storage_pvc import (
    ConnectionPVCMap,
    StoragePVC,
    StoragePVCBase,
    StoragePVCCreate,
    StoragePVCUpdate,
)

# Import schemas separately if needed
from desktop_manager.api.schemas.connection import (
    ConnectionBase,
    ConnectionCreate,
    ConnectionUpdate,
)
from desktop_manager.api.schemas.desktop_configuration import (
    DesktopConfigurationBase,
    DesktopConfigurationCreate,
    DesktopConfigurationUpdate,
)
from desktop_manager.api.schemas.user import UserBase, UserCreate


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
