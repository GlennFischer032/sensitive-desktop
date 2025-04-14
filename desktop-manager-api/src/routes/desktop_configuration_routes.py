from http import HTTPStatus
import logging
from typing import Any

from core.auth import admin_required, token_required
from database.core.session import with_db_session
from flask import Blueprint, jsonify, request
from services.connections import APIError
from services.desktop_configuration import DesktopConfigurationService


desktop_config_bp = Blueprint("desktop_config_bp", __name__)


@desktop_config_bp.route("/list", methods=["GET"])
@with_db_session
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

        # Create service instance and call list_configurations
        config_service = DesktopConfigurationService()
        response_data = config_service.list_configurations(current_user, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in list_configurations: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logging.error("Error listing desktop configurations: %s", str(e))
        return (
            jsonify({"error": "Internal server error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@desktop_config_bp.route("/create", methods=["POST"])
@with_db_session
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
        # Get input data
        data = request.get_json()
        current_user = request.current_user
        # Create service instance and call create_configuration
        config_service = DesktopConfigurationService()
        response_data = config_service.create_configuration(data, current_user, request.db_session)

        return jsonify(response_data), HTTPStatus.CREATED

    except APIError as e:
        logging.error("API error in create_configuration: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logging.error("Error creating desktop configuration: %s", str(e))
        return (
            jsonify({"error": "Internal server error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@desktop_config_bp.route("/update/<int:config_id>", methods=["PUT"])
@with_db_session
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
        # Get input data
        data = request.get_json()

        # Create service instance and call update_configuration
        config_service = DesktopConfigurationService()
        response_data = config_service.update_configuration(config_id, data, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in update_configuration: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logging.error("Error updating desktop configuration: %s", str(e))
        return (
            jsonify({"error": "Internal server error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@desktop_config_bp.route("/get/<int:config_id>", methods=["GET"])
@with_db_session
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

        # Create service instance and call get_configuration
        config_service = DesktopConfigurationService()
        response_data = config_service.get_configuration(config_id, current_user, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in get_configuration: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logging.error("Error getting desktop configuration: %s", str(e))
        return (
            jsonify({"error": "Internal server error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@desktop_config_bp.route("/delete/<int:config_id>", methods=["DELETE"])
@with_db_session
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
        # Create service instance and call delete_configuration
        config_service = DesktopConfigurationService()
        response_data = config_service.delete_configuration(config_id, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in delete_configuration: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logging.error("Error deleting desktop configuration: %s", str(e))
        return (
            jsonify({"error": "Internal server error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@desktop_config_bp.route("/access/<int:config_id>", methods=["GET"])
@with_db_session
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
        # Create service instance and call get_configuration_access
        config_service = DesktopConfigurationService()
        response_data = config_service.get_configuration_access(config_id, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in get_configuration_access: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logging.error("Error getting configuration access: %s", str(e))
        return (
            jsonify({"error": "Internal server error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@desktop_config_bp.route("/accessible", methods=["GET"])
@with_db_session
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

        # Create service instance and call list_accessible_configurations
        config_service = DesktopConfigurationService()
        response_data = config_service.list_accessible_configurations(current_user, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in list_accessible_configurations: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logging.error("Error listing accessible desktop configurations: %s", str(e))
        return (
            jsonify({"error": "Internal server error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )
