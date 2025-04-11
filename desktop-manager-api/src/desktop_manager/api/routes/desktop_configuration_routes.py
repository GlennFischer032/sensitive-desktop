from http import HTTPStatus
import logging
from typing import Any

from flask import Blueprint, jsonify, request

from desktop_manager.clients.factory import client_factory
from desktop_manager.core.auth import admin_required, token_required
from desktop_manager.database.core.session import get_db_session
from desktop_manager.database.repositories.desktop_configuration import DesktopConfigurationRepository


desktop_config_bp = Blueprint("desktop_config_bp", __name__)


@desktop_config_bp.route("/list", methods=["GET"])
@token_required
def list_configurations() -> tuple[dict[str, Any], int]:
    """List desktop configurations.

    This endpoint returns a list of desktop configurations,
    filtering based on user permissions.

    For admin users, all configurations are returned.
    For non-admin users, only public configurations and those
    they have explicit access to are returned.

    Returns:
        tuple: A tuple containing:
            - Dict with list of configurations
            - HTTP status code
    """
    try:
        # Get authenticated user
        current_user = request.current_user

        with get_db_session() as session:
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
                        "created_by": config.created_by,
                        "is_public": config.is_public,
                        "min_cpu": config.min_cpu,
                        "max_cpu": config.max_cpu,
                        "min_ram": config.min_ram,
                        "max_ram": config.max_ram,
                        "allowed_users": allowed_users,
                    }
                )

            return jsonify({"configurations": result}), HTTPStatus.OK

    except Exception as e:
        logging.error("Error listing desktop configurations: %s", str(e))
        return (
            jsonify({"error": "Internal server error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@desktop_config_bp.route("/create", methods=["POST"])
@token_required
@admin_required
def create_configuration() -> tuple[dict[str, Any], int]:
    """Create a new desktop configuration.

    This endpoint creates a new desktop configuration with the provided details.

    Returns:
        tuple: A tuple containing:
            - Dict with the created configuration
            - HTTP status code
    """
    try:
        # Get authenticated user
        current_user = request.current_user

        # Validate input data
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), HTTPStatus.BAD_REQUEST

        required_fields = ["name", "image"]
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return (
                jsonify({"error": f"Missing required fields: {', '.join(missing_fields)}"}),
                HTTPStatus.BAD_REQUEST,
            )

        with get_db_session() as session:
            desktop_config_repo = DesktopConfigurationRepository(session)

            # Check if configuration with this name already exists
            existing = desktop_config_repo.get_by_name(data["name"])
            if existing:
                return (
                    jsonify({"error": f"Configuration with name '{data['name']}' already exists"}),
                    HTTPStatus.CONFLICT,
                )
            config = desktop_config_repo.create_configuration(
                {
                    "name": data["name"],
                    "description": data.get("description", ""),
                    "image": data["image"],
                    "created_by": current_user.username,
                    "is_public": data.get("is_public", False),
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

            return jsonify(
                {
                    "configuration": {
                        "id": config.id,
                        "name": config.name,
                        "description": config.description,
                        "image": config.image,
                        "created_at": config.created_at.isoformat() if config.created_at else None,
                        "created_by": config.created_by,
                        "is_public": config.is_public,
                        "min_cpu": config.min_cpu,
                        "max_cpu": config.max_cpu,
                        "min_ram": config.min_ram,
                        "max_ram": config.max_ram,
                        "allowed_users": allowed_users,
                    }
                }
            ), HTTPStatus.CREATED

    except Exception as e:
        logging.error("Error creating desktop configuration: %s", str(e))
        return (
            jsonify({"error": "Internal server error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@desktop_config_bp.route("/update/<int:config_id>", methods=["PUT"])
@token_required
@admin_required
def update_configuration(config_id: int) -> tuple[dict[str, Any], int]:
    """Update an existing desktop configuration.

    This endpoint updates an existing desktop configuration with the provided details.

    Args:
        config_id: The ID of the configuration to update

    Returns:
        tuple: A tuple containing:
            - Dict with the updated configuration
            - HTTP status code
    """
    try:
        # Get authenticated user

        # Validate input data
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), HTTPStatus.BAD_REQUEST

        required_fields = ["name", "image"]
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return (
                jsonify({"error": f"Missing required fields: {', '.join(missing_fields)}"}),
                HTTPStatus.BAD_REQUEST,
            )

        # Get database client
        client_factory.get_database_client()

        with get_db_session() as session:
            desktop_config_repo = DesktopConfigurationRepository(session)
            # Check if configuration exists
            existing = desktop_config_repo.get_by_id(config_id)
            if not existing:
                return (
                    jsonify({"error": f"Configuration with ID {config_id} not found"}),
                    HTTPStatus.NOT_FOUND,
                )

            # Check if name is already used by another configuration
            name_check = desktop_config_repo.get_by_name(data["name"])
            if name_check and name_check.id != config_id:
                return (
                    jsonify({"error": f"Configuration with name '{data['name']}' already exists"}),
                    HTTPStatus.CONFLICT,
                )

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

            return jsonify(
                {
                    "configuration": {
                        "id": updated_config.id,
                        "name": updated_config.name,
                        "description": updated_config.description,
                        "image": updated_config.image,
                        "created_at": updated_config.created_at.isoformat() if updated_config.created_at else None,
                        "created_by": updated_config.created_by,
                        "is_public": updated_config.is_public,
                        "min_cpu": updated_config.min_cpu,
                        "max_cpu": updated_config.max_cpu,
                        "min_ram": updated_config.min_ram,
                        "max_ram": updated_config.max_ram,
                        "allowed_users": allowed_users,
                    }
                }
            ), HTTPStatus.OK

    except Exception as e:
        logging.error("Error updating desktop configuration: %s", str(e))
        return (
            jsonify({"error": "Internal server error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@desktop_config_bp.route("/get/<int:config_id>", methods=["GET"])
@token_required
def get_configuration(config_id: int) -> tuple[dict[str, Any], int]:
    """Get a specific desktop configuration.

    This endpoint returns detailed information about a specific desktop configuration.
    Users can only access configurations they have permission to view.

    Args:
        config_id: The ID of the configuration to retrieve

    Returns:
        tuple: A tuple containing:
            - Dict with the configuration details
            - HTTP status code
    """
    try:
        # Get authenticated user
        current_user = request.current_user

        with get_db_session() as session:
            desktop_config_repo = DesktopConfigurationRepository(session)
            # Get the configuration
            if current_user.is_admin:
                # Admins can see any configuration
                config = desktop_config_repo.get_by_id(config_id)
            else:
                # Non-admins can only see public configurations or those they have access to
                config = desktop_config_repo.get_configurations_for_user(current_user.username, config_id)

            if not config:
                return (
                    jsonify({"error": f"Configuration with ID {config_id} not found or access denied"}),
                    HTTPStatus.NOT_FOUND,
                )

            # Get access information
            access_list = desktop_config_repo.get_access_entries(config_id)
            allowed_users = [user.username for user in access_list]

            # Format the response
            response = {
                "id": config.id,
                "name": config.name,
                "description": config.description,
                "image": config.image,
                "created_at": config.created_at.isoformat() if config.created_at else None,
                "created_by": config.created_by,
                "is_public": config.is_public,
                "min_cpu": config.min_cpu,
                "max_cpu": config.max_cpu,
                "min_ram": config.min_ram,
                "max_ram": config.max_ram,
                "allowed_users": allowed_users,
            }

            return jsonify({"configuration": response}), HTTPStatus.OK

    except Exception as e:
        logging.error("Error getting desktop configuration: %s", str(e))
        return (
            jsonify({"error": "Internal server error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@desktop_config_bp.route("/delete/<int:config_id>", methods=["DELETE"])
@token_required
@admin_required
def delete_configuration(config_id: int) -> tuple[dict[str, Any], int]:
    """Delete a desktop configuration.

    This endpoint deletes a desktop configuration by ID.
    Only administrators can delete configurations.

    Args:
        config_id: The ID of the configuration to delete

    Returns:
        tuple: A tuple containing:
            - Dict with the operation result
            - HTTP status code
    """
    try:
        # Get authenticated user

        # Get database client
        with get_db_session() as session:
            desktop_config_repo = DesktopConfigurationRepository(session)
            # Check if configuration exists
            existing = desktop_config_repo.get_by_id(config_id)
            if not existing:
                return (
                    jsonify({"error": f"Configuration with ID {config_id} not found"}),
                    HTTPStatus.NOT_FOUND,
                )

            if desktop_config_repo.is_in_use(config_id):
                return (
                    jsonify(
                        {
                            "error": f"Cannot delete configuration with ID {config_id}"
                            " because it is being used by a connection"
                        }
                    ),
                    HTTPStatus.CONFLICT,
                )

            # Delete access records first
            desktop_config_repo.clear_access(config_id)

            # Delete the configuration
            desktop_config_repo.delete_configuration(config_id)

            return jsonify({"message": f"Configuration with ID {config_id} deleted successfully"}), HTTPStatus.OK

    except Exception as e:
        logging.error("Error deleting desktop configuration: %s", str(e))
        return (
            jsonify({"error": "Internal server error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@desktop_config_bp.route("/access/<int:config_id>", methods=["GET"])
@token_required
@admin_required
def get_configuration_access(config_id: int) -> tuple[dict[str, Any], int]:
    """Get users with access to a specific configuration.

    This endpoint returns a list of users who have access to a private configuration.

    Args:
        config_id: The ID of the configuration

    Returns:
        tuple: A tuple containing:
            - Dict with the list of users
            - HTTP status code
    """
    try:
        # Get authenticated user

        with get_db_session() as session:
            desktop_config_repo = DesktopConfigurationRepository(session)
            # Check if configuration exists
            existing = desktop_config_repo.get_by_id(config_id)
            if not existing:
                return (
                    jsonify({"error": f"Configuration with ID {config_id} not found"}),
                    HTTPStatus.NOT_FOUND,
                )

            # Get users with access
            users = desktop_config_repo.get_users_with_access(config_id)

            return jsonify({"users": users}), HTTPStatus.OK

    except Exception as e:
        logging.error("Error getting configuration access: %s", str(e))
        return (
            jsonify({"error": "Internal server error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@desktop_config_bp.route("/accessible", methods=["GET"])
@token_required
def list_accessible_configurations() -> tuple[dict[str, Any], int]:
    """List desktop configurations accessible to the current user.

    This endpoint returns a simplified list of desktop configurations
    that the current user can use for creating new connections.

    Returns:
        tuple: A tuple containing:
            - Dict with list of configurations
            - HTTP status code
    """
    try:
        # Get authenticated user
        current_user = request.current_user

        with get_db_session() as session:
            desktop_config_repo = DesktopConfigurationRepository(session)
            if current_user.is_admin:
                # Admins can see all configurations
                configurations = desktop_config_repo.get_all_configurations()
            else:
                # Non-admins can see public configurations and ones they have access to
                configurations = desktop_config_repo.get_configurations_for_user(current_user.username)

            return jsonify({"configurations": configurations}), HTTPStatus.OK

    except Exception as e:
        logging.error("Error listing accessible desktop configurations: %s", str(e))
        return (
            jsonify({"error": "Internal server error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )
