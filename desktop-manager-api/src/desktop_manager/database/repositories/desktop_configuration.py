"""Desktop configuration repository module.

This module provides a repository for desktop configuration operations.
"""

from typing import Any

from sqlalchemy import or_
from sqlalchemy.orm import Session

from desktop_manager.database.models.connection import Connection
from desktop_manager.database.models.desktop_configuration import DesktopConfiguration, DesktopConfigurationAccess
from desktop_manager.database.repositories.base import BaseRepository


class DesktopConfigurationRepository(BaseRepository[DesktopConfiguration]):
    """Repository for desktop configuration operations.

    This class provides methods for desktop configuration-specific operations such as creating,
    updating, and retrieving desktop configurations, as well as managing user access.
    """

    def __init__(self, session: Session):
        """Initialize the repository with a session.

        Args:
            session: SQLAlchemy session for database operations
        """
        super().__init__(session, DesktopConfiguration)

    def get_by_name(self, name: str) -> DesktopConfiguration | None:
        """Get a desktop configuration by name.

        Args:
            name: Configuration name

        Returns:
            DesktopConfiguration if found, None otherwise
        """
        return self.session.query(DesktopConfiguration).filter(DesktopConfiguration.name == name).first()

    def get_by_id(self, config_id: int) -> DesktopConfiguration | None:
        """Get a desktop configuration by ID.

        Args:
            config_id: Configuration ID

        Returns:
            DesktopConfiguration if found, None otherwise
        """
        return self.session.query(DesktopConfiguration).filter(DesktopConfiguration.id == config_id).first()

    def create_configuration(self, data: dict[str, Any]) -> DesktopConfiguration:
        """Create a new desktop configuration.

        Args:
            data: Configuration data

        Returns:
            Newly created desktop configuration
        """
        config = DesktopConfiguration(
            name=data["name"],
            description=data.get("description", ""),
            image=data["image"],
            created_by=data["created_by"],
            is_public=data.get("is_public", False),
            min_cpu=data.get("min_cpu", 1),
            max_cpu=data.get("max_cpu", 4),
            min_ram=data.get("min_ram", "4096Mi"),
            max_ram=data.get("max_ram", "16384Mi"),
        )
        return self.create(config)

    def update_configuration(self, config_id: int, data: dict[str, Any]) -> DesktopConfiguration | None:
        """Update a desktop configuration.

        Args:
            config_id: Configuration ID
            data: Updated configuration data

        Returns:
            Updated desktop configuration if found, None otherwise
        """
        config = self.get_by_id(config_id)
        if config:
            if "name" in data:
                config.name = data["name"]
            if "description" in data:
                config.description = data["description"]
            if "image" in data:
                config.image = data["image"]
            if "is_public" in data:
                config.is_public = data["is_public"]
            if "min_cpu" in data:
                config.min_cpu = data["min_cpu"]
            if "max_cpu" in data:
                config.max_cpu = data["max_cpu"]
            if "min_ram" in data:
                config.min_ram = data["min_ram"]
            if "max_ram" in data:
                config.max_ram = data["max_ram"]

            self.update(config)
        return config

    def delete_configuration(self, config_id: int) -> bool:
        """Delete a desktop configuration.

        Args:
            config_id: Configuration ID

        Returns:
            True if configuration was deleted, False otherwise
        """
        config = self.get_by_id(config_id)
        if config:
            self.session.delete(config)
            self.session.commit()
            return True
        return False

    def get_all_configurations(self) -> list[DesktopConfiguration]:
        """Get all desktop configurations.

        Returns:
            List of all desktop configurations
        """
        return self.session.query(DesktopConfiguration).order_by(DesktopConfiguration.name).all()

    def get_configurations_for_user(self, username: str) -> list[DesktopConfiguration]:
        """Get desktop configurations accessible to a specific user.

        This includes:
        - Public configurations
        - Configurations explicitly accessible to the user

        Args:
            username: Username

        Returns:
            List of accessible desktop configurations
        """
        return (
            self.session.query(DesktopConfiguration)
            .filter(
                or_(
                    DesktopConfiguration.is_public is True,
                    DesktopConfiguration.id.in_(
                        self.session.query(DesktopConfigurationAccess.desktop_configuration_id).filter(
                            DesktopConfigurationAccess.username == username
                        )
                    ),
                )
            )
            .order_by(DesktopConfiguration.name)
            .all()
        )

    def get_configurations_created_by(self, username: str) -> list[DesktopConfiguration]:
        """Get desktop configurations created by a specific user.

        Args:
            username: Username of creator

        Returns:
            List of desktop configurations created by the user
        """
        return (
            self.session.query(DesktopConfiguration)
            .filter(DesktopConfiguration.created_by == username)
            .order_by(DesktopConfiguration.name)
            .all()
        )

    # Access control methods
    def create_access(self, config_id: int, username: str) -> DesktopConfigurationAccess:
        """Grant access to a desktop configuration.

        Args:
            config_id: Configuration ID
            username: Username to grant access to

        Returns:
            Created access entry
        """
        access = DesktopConfigurationAccess(
            desktop_configuration_id=config_id,
            username=username,
        )
        self.session.add(access)
        self.session.commit()
        return access

    def clear_access(self, config_id: int) -> None:
        """Clear all access entries for a desktop configuration.

        Args:
            config_id: Configuration ID
        """
        self.session.query(DesktopConfigurationAccess).filter(
            DesktopConfigurationAccess.desktop_configuration_id == config_id
        ).delete()
        self.session.commit()

    def get_access_entries(self, config_id: int) -> list[DesktopConfigurationAccess]:
        """Get all access entries for a desktop configuration.

        Args:
            config_id: Configuration ID

        Returns:
            List of access entries
        """
        return (
            self.session.query(DesktopConfigurationAccess)
            .filter(DesktopConfigurationAccess.desktop_configuration_id == config_id)
            .all()
        )

    def get_users_with_access(self, config_id: int) -> list[str]:
        """Get usernames with access to a desktop configuration.

        Args:
            config_id: Configuration ID

        Returns:
            List of usernames with access
        """
        access_entries = self.get_access_entries(config_id)
        return [access.username for access in access_entries]

    def is_in_use(self, config_id: int) -> bool:
        """Check if a desktop configuration is in use by any connection.

        Args:
            config_id: Configuration ID

        Returns:
            True if in use, False otherwise
        """
        from desktop_manager.database.models.connection import Connection

        count = self.session.query(Connection).filter(Connection.desktop_configuration_id == config_id).count()
        return count > 0

    def get_connections_for_configuration(self, config_id: int) -> list[Connection]:
        """Get all connections for a desktop configuration.

        Args:
            config_id: Configuration ID

        Returns:
            List of connections
        """
        return self.session.query(Connection).filter(Connection.desktop_configuration_id == config_id).all()
