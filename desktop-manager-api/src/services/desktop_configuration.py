import logging

from database.repositories.desktop_configuration import DesktopConfigurationRepository
from services.connections import APIError, BadRequestError, NotFoundError


class DesktopConfigurationService:
    """Service for managing desktop configurations."""

    def list_configurations(self, current_user, session):
        """List desktop configurations based on user permissions."""
        try:
            desktop_config_repo = DesktopConfigurationRepository(session)
            if current_user.is_admin:
                # Admins can see all configurations
                configurations = desktop_config_repo.get_all_configurations()
            else:
                # Non-admins can see public configurations and ones they have access to
                configurations = desktop_config_repo.get_configurations_for_user(current_user.username)

            # Add user access information to each configuration
            result = []

            for config in configurations:
                access_list = desktop_config_repo.get_access_entries(config.id)
                allowed_users = [user.username for user in access_list]

                result.append(
                    {
                        "id": config.id,
                        "name": config.name,
                        "description": config.description,
                        "image": config.image,
                        "created_at": config.created_at.isoformat() if config.created_at else None,
                        "is_public": config.is_public,
                        "min_cpu": config.min_cpu,
                        "max_cpu": config.max_cpu,
                        "min_ram": config.min_ram,
                        "max_ram": config.max_ram,
                        "allowed_users": allowed_users,
                    }
                )

            return {"configurations": result}
        except Exception as e:
            logging.error("Error listing desktop configurations: %s", str(e))
            raise APIError(f"Failed to list configurations: {e!s}") from e

    def create_configuration(self, data, current_user, session):
        """Create a new desktop configuration."""
        try:
            # Validate input data
            if not data:
                raise BadRequestError("No data provided")

            required_fields = ["name", "image"]
            missing_fields = [field for field in required_fields if field not in data]
            if missing_fields:
                raise BadRequestError(f"Missing required fields: {', '.join(missing_fields)}")

            desktop_config_repo = DesktopConfigurationRepository(session)

            # Check if configuration with this name already exists
            existing = desktop_config_repo.get_by_name(data["name"])
            if existing:
                raise BadRequestError(f"Configuration with name '{data['name']}' already exists")

            config = desktop_config_repo.create_configuration(
                {
                    "name": data["name"],
                    "description": data.get("description", ""),
                    "image": data["image"],
                    "is_public": data.get("is_public", False),
                    "created_by": current_user.username,
                    "min_cpu": data.get("min_cpu", 1),
                    "max_cpu": data.get("max_cpu", 4),
                    "min_ram": data.get("min_ram", "4096Mi"),
                    "max_ram": data.get("max_ram", "16384Mi"),
                }
            )

            # Process user access if provided
            allowed_users = data.get("allowed_users", [])
            if allowed_users and not config.is_public:
                # Insert access records
                for username in allowed_users:
                    desktop_config_repo.create_access(config.id, username)

            return {
                "configuration": {
                    "id": config.id,
                    "name": config.name,
                    "description": config.description,
                    "image": config.image,
                    "created_at": config.created_at.isoformat() if config.created_at else None,
                    "is_public": config.is_public,
                    "min_cpu": config.min_cpu,
                    "max_cpu": config.max_cpu,
                    "min_ram": config.min_ram,
                    "max_ram": config.max_ram,
                    "allowed_users": allowed_users,
                }
            }
        except APIError:
            # Re-raise API errors
            raise
        except Exception as e:
            logging.error("Error creating desktop configuration: %s", str(e))
            raise APIError(f"Failed to create configuration: {e!s}") from e

    def update_configuration(self, config_id, data, session):
        """Update an existing desktop configuration."""
        try:
            # Validate input data
            if not data:
                raise BadRequestError("No data provided")

            required_fields = ["name", "image"]
            missing_fields = [field for field in required_fields if field not in data]
            if missing_fields:
                raise BadRequestError(f"Missing required fields: {', '.join(missing_fields)}")

            desktop_config_repo = DesktopConfigurationRepository(session)

            # Check if configuration exists
            existing = desktop_config_repo.get_by_id(config_id)
            if not existing:
                raise NotFoundError(f"Configuration with ID {config_id} not found")

            # Check if name is already used by another configuration
            name_check = desktop_config_repo.get_by_name(data["name"])
            if name_check and name_check.id != config_id:
                raise BadRequestError(f"Configuration with name '{data['name']}' already exists")

            update_data = {
                "id": config_id,
                "name": data["name"],
                "description": data.get("description", ""),
                "image": data["image"],
                "is_public": data.get("is_public", False),
                "min_cpu": data.get("min_cpu", 1),
                "max_cpu": data.get("max_cpu", 4),
                "min_ram": data.get("min_ram", "4096Mi"),
                "max_ram": data.get("max_ram", "16384Mi"),
            }

            updated_config = desktop_config_repo.update_configuration(config_id, update_data)

            # Update user access if provided
            allowed_users = data.get("allowed_users", [])

            # Clear existing access records
            desktop_config_repo.clear_access(config_id)

            # Insert new access records if not public
            if allowed_users and not updated_config.is_public:
                for username in allowed_users:
                    desktop_config_repo.create_access(config_id, username)

            return {
                "configuration": {
                    "id": updated_config.id,
                    "name": updated_config.name,
                    "description": updated_config.description,
                    "image": updated_config.image,
                    "created_at": updated_config.created_at.isoformat() if updated_config.created_at else None,
                    "is_public": updated_config.is_public,
                    "min_cpu": updated_config.min_cpu,
                    "max_cpu": updated_config.max_cpu,
                    "min_ram": updated_config.min_ram,
                    "max_ram": updated_config.max_ram,
                    "allowed_users": allowed_users,
                }
            }
        except APIError:
            # Re-raise API errors
            raise
        except Exception as e:
            logging.error("Error updating desktop configuration: %s", str(e))
            raise APIError(f"Failed to update configuration: {e!s}") from e

    def get_configuration(self, config_id, current_user, session):
        """Get a specific desktop configuration."""
        try:
            desktop_config_repo = DesktopConfigurationRepository(session)

            # Get the configuration
            if current_user.is_admin:
                # Admins can see any configuration
                config = desktop_config_repo.get_by_id(config_id)
            else:
                # Non-admins can only see public configurations or those they have access to
                config = desktop_config_repo.get_configurations_for_user(current_user.username, config_id)

            if not config:
                raise NotFoundError(f"Configuration with ID {config_id} not found or access denied")

            # Get access information
            access_list = desktop_config_repo.get_access_entries(config_id)
            allowed_users = [user.username for user in access_list]

            # Format the response
            return {
                "configuration": {
                    "id": config.id,
                    "name": config.name,
                    "description": config.description,
                    "image": config.image,
                    "created_at": config.created_at.isoformat() if config.created_at else None,
                    "is_public": config.is_public,
                    "min_cpu": config.min_cpu,
                    "max_cpu": config.max_cpu,
                    "min_ram": config.min_ram,
                    "max_ram": config.max_ram,
                    "allowed_users": allowed_users,
                }
            }
        except APIError:
            # Re-raise API errors
            raise
        except Exception as e:
            logging.error("Error getting desktop configuration: %s", str(e))
            raise APIError(f"Failed to get configuration: {e!s}") from e

    def delete_configuration(self, config_id, session):
        """Delete a desktop configuration."""
        try:
            desktop_config_repo = DesktopConfigurationRepository(session)

            # Check if configuration exists
            existing = desktop_config_repo.get_by_id(config_id)
            if not existing:
                raise NotFoundError(f"Configuration with ID {config_id} not found")

            if desktop_config_repo.is_in_use(config_id):
                raise BadRequestError(
                    f"Cannot delete configuration with ID {config_id} because it is being used by a connection"
                )

            # Delete access records first
            desktop_config_repo.clear_access(config_id)

            # Delete the configuration
            desktop_config_repo.delete_configuration(config_id)

            return {"message": f"Configuration with ID {config_id} deleted successfully"}
        except APIError:
            # Re-raise API errors
            raise
        except Exception as e:
            logging.error("Error deleting desktop configuration: %s", str(e))
            raise APIError(f"Failed to delete configuration: {e!s}") from e

    def get_configuration_access(self, config_id, session):
        """Get users with access to a specific configuration."""
        try:
            desktop_config_repo = DesktopConfigurationRepository(session)

            # Check if configuration exists
            existing = desktop_config_repo.get_by_id(config_id)
            if not existing:
                raise NotFoundError(f"Configuration with ID {config_id} not found")

            # Get users with access
            users = desktop_config_repo.get_users_with_access(config_id)

            return {"users": users}
        except APIError:
            # Re-raise API errors
            raise
        except Exception as e:
            logging.error("Error getting configuration access: %s", str(e))
            raise APIError(f"Failed to get configuration access: {e!s}") from e

    def list_accessible_configurations(self, current_user, session):
        """List desktop configurations accessible to the current user."""
        try:
            desktop_config_repo = DesktopConfigurationRepository(session)
            if current_user.is_admin:
                # Admins can see all configurations
                configurations = desktop_config_repo.get_all_configurations()
            else:
                # Non-admins can see public configurations and ones they have access to
                configurations = desktop_config_repo.get_configurations_for_user(current_user.username)

            return {"configurations": configurations}
        except Exception as e:
            logging.error("Error listing accessible desktop configurations: %s", str(e))
            raise APIError(f"Failed to list accessible configurations: {e!s}") from e
