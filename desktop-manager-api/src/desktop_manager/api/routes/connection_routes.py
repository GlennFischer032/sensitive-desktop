from http import HTTPStatus
import logging
import re
from typing import Any
import uuid

from flask import Blueprint, jsonify, request

from desktop_manager.clients.factory import client_factory
from desktop_manager.clients.rancher import DesktopValues
from desktop_manager.config.settings import get_settings
from desktop_manager.core.auth import token_required
from desktop_manager.database.core.session import get_db_session
from desktop_manager.database.repositories.connection import ConnectionRepository
from desktop_manager.database.repositories.desktop_configuration import DesktopConfigurationRepository
from desktop_manager.database.repositories.storage_pvc import StoragePVCRepository
from desktop_manager.utils.guacamole_json_auth import GuacamoleJsonAuth
from desktop_manager.utils.utils import (
    generate_random_string,
    generate_unique_connection_name,
)


connections_bp = Blueprint("connections_bp", __name__)


# Custom exceptions for different error types
class APIError(Exception):
    """Base exception for API errors."""

    def __init__(self, message, status_code=HTTPStatus.INTERNAL_SERVER_ERROR):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class BadRequestError(APIError):
    """Raised when client sends invalid or incomplete data."""

    def __init__(self, message):
        super().__init__(message, HTTPStatus.BAD_REQUEST)


class NotFoundError(APIError):
    """Raised when a requested resource is not found."""

    def __init__(self, message):
        super().__init__(message, HTTPStatus.NOT_FOUND)


class ForbiddenError(APIError):
    """Raised when user doesn't have permission to access a resource."""

    def __init__(self, message):
        super().__init__(message, HTTPStatus.FORBIDDEN)


class UnauthorizedError(APIError):
    """Raised when authentication is required but missing or invalid."""

    def __init__(self, message):
        super().__init__(message, HTTPStatus.UNAUTHORIZED)


@connections_bp.route("/scaleup", methods=["POST"])
@token_required
def scale_up() -> tuple[dict[str, Any], int]:
    """Scale up a new desktop connection.

    This endpoint creates a new desktop connection by:
    1. Validating the input data
    2. Creating a Rancher deployment
    3. Creating a Guacamole connection
    4. Storing the connection details in the database

    Returns:
        tuple: A tuple containing:
            - Dict with connection details or error message
            - HTTP status code
    """
    logging.info("=== Received request to /scaleup ===")
    logging.info("Request path: %s", request.path)
    logging.info("Request method: %s", request.method)
    logging.info("Request headers: %s", request.headers)

    try:
        # Validate input data
        data = request.get_json()
        current_user = request.current_user

        # Validate request data
        _validate_scale_up_input(data)

        # Extract and validate parameters
        persistent_home = data.get("persistent_home", True)
        external_pvc = data.get("external_pvc")

        # Validate external PVC if provided
        if external_pvc:
            _validate_external_pvc(external_pvc, current_user)

        # Get desktop configuration
        desktop_image, min_cpu, max_cpu, min_ram, max_ram, desktop_configuration_id = _get_desktop_configuration(
            data.get("desktop_configuration_id"), current_user
        )

        # Generate unique connection name and credentials
        name = generate_unique_connection_name(data["name"])
        logging.info("Generated unique name: %s", name)
        vnc_password = generate_random_string(32)
        logging.info("Generated VNC password")

        # Provision resources
        status, rancher_client = _provision_desktop_resources(
            name, vnc_password, desktop_image, min_cpu, max_cpu, min_ram, max_ram, persistent_home, external_pvc
        )

        try:
            # Setup Guacamole connection
            guacamole_connection_id = _setup_guacamole_connection(name, vnc_password, current_user.username)

            # Save to database
            _save_connection_to_database(
                name,
                current_user.username,
                guacamole_connection_id,
                persistent_home,
                desktop_configuration_id,
                external_pvc,
            )

            # Return connection details
            response_data = {
                "name": name,
                "created_by": current_user.username,
                "is_stopped": False,
                "persistent_home": persistent_home,
                "desktop_configuration_id": desktop_configuration_id,
                "status": status,
                "vnc_password": vnc_password,
                "guacamole_connection_id": guacamole_connection_id,
                "external_pvc": external_pvc,  # Include PVC info in response
            }

            return jsonify(response_data), HTTPStatus.OK

        except Exception as e:
            # Clean up Rancher deployment if an error occurred after it was created
            try:
                rancher_client.uninstall(name)
                logging.info("Cleaned up Rancher deployment after error")
            except Exception as cleanup_error:
                logging.error("Failed to clean up Rancher deployment: %s", str(cleanup_error))
            raise e

    except APIError as e:
        logging.error("API error in scale_up: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logging.error("Unexpected error in scale_up: %s", str(e))
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


def _validate_scale_up_input(data: dict):
    """Validate the input data for the scale_up endpoint."""
    if not data or "name" not in data:
        raise BadRequestError("Missing required field: name")

    # Validate name against the required pattern
    name_pattern = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")
    if not name_pattern.match(data["name"]):
        raise BadRequestError(
            "Connection name must start and end with an alphanumeric character "
            "and contain only lowercase letters, numbers, and hyphens"
        )

    # Check if name is too long (max 12 characters)
    if len(data["name"]) > 12:
        raise BadRequestError("Connection name is too long. Maximum length is 12 characters.")


def _validate_external_pvc(external_pvc: str, current_user):
    """Validate that the external PVC exists and the user has access to it."""
    logging.info("External PVC specified: %s", external_pvc)
    try:
        with get_db_session() as session:
            pvc_repo = StoragePVCRepository(session)
            pvc = pvc_repo.get_by_name(external_pvc)
            if not pvc:
                raise NotFoundError(f"PVC '{external_pvc}' not found")

            allowed_users = [access.username for access in pvc.access_permissions]

            if current_user.is_admin:
                logging.info("Admin user - access granted to PVC")
            elif pvc["is_public"]:
                logging.info("Public PVC - access granted to all users")
            elif current_user.username not in allowed_users:
                raise ForbiddenError("You do not have permission to use this PVC")

            return pvc.id

    except APIError:
        # Re-raise API errors
        raise
    except Exception as e:
        logging.error("Error verifying PVC: %s", str(e))
        raise APIError(f"Error verifying PVC: {e!s}") from e


def _get_desktop_configuration(desktop_configuration_id, current_user):
    """Get desktop configuration details.

    Returns:
        Tuple[str, int, int, str, str, Optional[int]]:
            (desktop_image, min_cpu, max_cpu, min_ram, max_ram, desktop_configuration_id)
    """
    if desktop_configuration_id:
        with get_db_session() as session:
            config_repo = DesktopConfigurationRepository(session)
            config = config_repo.get_by_id(desktop_configuration_id)

            if not config:
                raise NotFoundError("Desktop configuration not found")

            allowed_users = config.user_access

            if not current_user.is_admin and current_user.username not in allowed_users:
                raise ForbiddenError("You do not have permission to use this configuration")

            desktop_image = config.image
            min_cpu = config.min_cpu
            max_cpu = config.max_cpu
            min_ram = config.min_ram
            max_ram = config.max_ram
    else:
        settings = get_settings()
        desktop_image = settings.DESKTOP_IMAGE
        desktop_configuration_id = None
        min_cpu = 1
        max_cpu = 4
        min_ram = "4096Mi"
        max_ram = "16384Mi"

    return desktop_image, min_cpu, max_cpu, min_ram, max_ram, desktop_configuration_id


def _provision_desktop_resources(
    name, vnc_password, desktop_image, min_cpu, max_cpu, min_ram, max_ram, persistent_home, external_pvc
):
    """Provision desktop resources using Rancher.

    Returns:
        Tuple[str, RancherClient]: (status, rancher_client)
    """
    # Create Rancher API client
    rancher_client = client_factory.get_rancher_client()

    # Create desktop values
    desktop_values = DesktopValues(
        desktop=desktop_image,
        name=name,
        vnc_password=vnc_password,
        mincpu=min_cpu,
        maxcpu=max_cpu,
        minram=min_ram,
        maxram=max_ram,
        external_pvc=external_pvc,
    )

    # Configure storage with persistent_home setting
    desktop_values.storage.persistenthome = persistent_home

    # Enable storage if external PVC is provided
    if external_pvc:
        desktop_values.storage.enable = True

    try:
        # Install Helm chart
        logging.info("Installing Helm chart for %s", name)
        rancher_client.install(name, desktop_values)
        logging.info("Helm chart installation completed")

        # Check if VNC server is ready
        logging.info("Checking if VNC server is ready for %s", name)
        vnc_ready = rancher_client.check_vnc_ready(name)
        status = "ready" if vnc_ready else "provisioning"
        logging.info("VNC server ready status for %s: %s", name, status)

        return status, rancher_client
    except Exception as e:
        logging.error("Rancher provisioning failed: %s", str(e))
        raise APIError(f"Failed to provision desktop: {e!s}") from e


def _setup_guacamole_connection(name, vnc_password, username):
    """Set up Guacamole connection for the desktop.

    Returns:
        str: guacamole_connection_id
    """
    try:
        # Get Guacamole client from factory
        guacamole_client = client_factory.get_guacamole_client()

        # Create Guacamole connection
        # First get a Guacamole token
        token = guacamole_client.login()

        # Ensure admins group exists
        guacamole_client.ensure_group(token, "admins")

        # Get settings here to ensure it's in scope
        settings = get_settings()

        # Use correct hostname format
        target_host = f"{settings.NAMESPACE}-{name}.dyn.cloud.e-infra.cz"

        guacamole_connection_id = guacamole_client.create_connection(
            token,
            name,
            target_host,
            vnc_password,
        )
        logging.info("Created Guacamole connection: %s", guacamole_connection_id)

        # Grant permission to admins group
        guacamole_client.grant_group_permission(token, "admins", guacamole_connection_id)

        # Grant permission to user
        guacamole_client.grant_permission(token, username, guacamole_connection_id)
        logging.debug("Granted permission to %s", username)

        return guacamole_connection_id
    except Exception as e:
        logging.error("Guacamole operation failed: %s", str(e))
        raise APIError(f"Failed to set up Guacamole connection: {e!s}") from e


def _save_connection_to_database(
    name, username, guacamole_connection_id, persistent_home, desktop_configuration_id, external_pvc
):
    """Save connection details to the database.

    Returns:
        Connection: The created connection
    """
    try:
        with get_db_session() as session:
            conn_repo = ConnectionRepository(session)
            connection = conn_repo.create_connection(
                {
                    "name": name,
                    "created_by": username,
                    "guacamole_connection_id": guacamole_connection_id,
                    "persistent_home": persistent_home,
                    "desktop_configuration_id": desktop_configuration_id,
                }
            )

            # If external PVC was used, map it to the connection
            if external_pvc:
                try:
                    pvc_repo = StoragePVCRepository(session)
                    pvc = pvc_repo.get_by_name(external_pvc)
                    if not pvc:
                        raise NotFoundError(f"PVC '{external_pvc}' not found")

                    conn_repo = ConnectionRepository(session)
                    conn_repo.map_connection_to_pvc(connection.id, pvc.id)

                except Exception as e:
                    logging.error("Error mapping connection to PVC: %s", str(e))
                # Continue even if mapping fails

        return connection
    except Exception as e:
        logging.error("Database error: %s", str(e))
        raise APIError(f"Failed to save connection: {e!s}") from e


@connections_bp.route("/scaledown", methods=["POST"])
@token_required
def scale_down() -> tuple[dict[str, Any], int]:
    """Scale down a desktop connection.

    This endpoint removes a desktop connection by:
    1. For connections with persistent_home=false:
       - Uninstalling the Rancher deployment
       - Deleting the Guacamole connection
       - Removing the connection details from the database
    2. For connections with persistent_home=true:
       - Uninstalling the Rancher deployment
       - Deleting the Guacamole connection
       - Marking the connection as deleted (soft delete)

    Returns:
        tuple: A tuple containing:
            - Dict with success/error message
            - HTTP status code
    """
    data = request.get_json()
    if not data or not data.get("name"):
        return (
            jsonify({"error": "Missing required field: name"}),
            HTTPStatus.BAD_REQUEST,
        )

    connection_name = data.get("name")
    logging.info("Processing scale down for connection: %s", connection_name)

    # Get the current user
    current_user = request.current_user
    logging.info("Current user: %s", current_user.username)

    try:
        with get_db_session() as session:
            conn_repo = ConnectionRepository(session)
            connection = conn_repo.get_by_name(connection_name)

            # Check if user has permission to delete this connection
            if not current_user.is_admin and connection.created_by != current_user.username:
                return (
                    jsonify({"error": "You do not have permission to delete this connection"}),
                    HTTPStatus.FORBIDDEN,
                )

            # Get Guacamole connection ID
            guacamole_connection_id = connection.guacamole_connection_id
            persistent_home = connection.persistent_home

            # Uninstall the Rancher deployment
            try:
                # Create Rancher API client
                rancher_client = client_factory.get_rancher_client()
                logging.info("Created Rancher client for uninstallation")

                # Uninstall the Helm chart
                rancher_client.uninstall(connection.name)
                logging.info("Uninstalled Helm chart for %s", connection.name)
                rancher_uninstall_success = True
            except Exception as e:
                rancher_uninstall_success = False
                logging.error("Failed to uninstall Rancher deployment: %s", str(e))
                # Continue to delete Guacamole connection and update database entry

            # Delete Guacamole connection
            try:
                guacamole_client = client_factory.get_guacamole_client()
                token = guacamole_client.login()
                guacamole_client.delete_connection(token, guacamole_connection_id)
                logging.info("Deleted Guacamole connection: %s", guacamole_connection_id)
                guacamole_delete_success = True
            except Exception as e:
                guacamole_delete_success = False
                logging.error("Failed to delete Guacamole connection: %s", str(e))

            # Check if we should soft delete or hard delete
            if persistent_home:
                # Soft delete - mark as stopped in the database
                conn_repo = ConnectionRepository(session)
                conn_repo.update_connection(connection.id, {"is_stopped": True})
                logging.info("Marked connection as stopped: %s", connection_name)

                message = f"Connection {connection_name} scaled down and preserved for future resumption"
            else:
                # Hard delete - remove from database
                conn_repo = ConnectionRepository(session)
                conn_repo.delete_connection(connection.id)
                logging.info("Hard deleted connection: %s", connection_name)

                message = f"Connection {connection_name} permanently deleted"

            # Return appropriate status based on what succeeded and what failed
            if not rancher_uninstall_success and not guacamole_delete_success:
                return (
                    jsonify(
                        {
                            "error": (
                                f"Failed to fully clean up {connection_name}. "
                                "Rancher deployment and Guacamole connection could not be removed."
                            )
                        }
                    ),
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            elif not rancher_uninstall_success:
                return (
                    jsonify({"message": (f"{message} with warnings: " "Rancher deployment could not be removed")}),
                    HTTPStatus.OK,
                )
            elif not guacamole_delete_success:
                return (
                    jsonify({"message": (f"{message} with warnings: " "Guacamole connection could not be removed")}),
                    HTTPStatus.OK,
                )
            else:
                return (
                    jsonify({"message": message}),
                    HTTPStatus.OK,
                )

    except Exception as e:
        logging.error("Error in scale_down: %s", str(e))
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@connections_bp.route("/list", methods=["GET"])
@token_required
def list_connections() -> tuple[dict[str, Any], int]:
    """List all connections for the current user.

    This endpoint retrieves all connections from the database
    and includes a single sign-on URL for each connection.

    For admin users, all connections are returned.
    For non-admin users, only connections created by the user are returned.

    Query Parameters:
        created_by (str, optional): Filter connections by creator username (admin only)

    Returns:
        tuple: A tuple containing:
            - Dict with list of connections
            - HTTP status code
    """
    try:
        # Get authenticated user
        current_user = request.current_user

        # Get optional creator filter (only effective for admin users)
        creator_filter = request.args.get("created_by")

        # Prepare the JSON auth utility
        GuacamoleJsonAuth()
        get_settings()

        with get_db_session() as session:
            conn_repo = ConnectionRepository(session)
            if current_user.is_admin:
                if creator_filter:
                    connections = conn_repo.get_connections_by_creator(creator_filter)
                else:
                    connections = conn_repo.get_all_connections()
            else:
                connections = conn_repo.get_connections_by_creator(current_user.username)

            result = []

            for connection in connections:
                # Add to result
                result.append(
                    {
                        "id": connection.id,
                        "name": connection.name,
                        "created_at": (connection.created_at.isoformat() if connection.created_at else None),
                        "created_by": connection.created_by,
                        "guacamole_connection_id": connection.guacamole_connection_id,
                        "persistent_home": connection.persistent_home,
                        "is_stopped": connection.is_stopped,
                        "desktop_configuration_id": connection.desktop_configuration_id,
                        "desktop_configuration_name": connection.desktop_configuration.name
                        if connection.desktop_configuration
                        else None,
                    }
                )

            return jsonify({"connections": result}), HTTPStatus.OK

    except Exception as e:
        logging.error("Error listing connections: %s", str(e))
        return (
            jsonify({"error": "Internal server error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@connections_bp.route("/<connection_name>", methods=["GET"])
@token_required
def get_connection(connection_name):
    """Get a connection.
    ---
    tags:
      - connections
    responses:
      200:
        description: Connection information
        content:
          application/json:
            schema:
              type: object
              properties:
                connection:
                  type: object
                  properties:
                    name:
                      type: string
                    created_at:
                      type: string
                    created_by:
                      type: string
      403:
        description: Forbidden - user does not have permission to access this connection
      404:
        description: Connection not found
      500:
        description: Internal server error.
    """
    logging.info("=== Received request to /%s ===", connection_name)
    logging.info("Request path: %s", request.path)
    logging.info("Request method: %s", request.method)
    logging.info("Request headers: %s", request.headers)

    # Get authenticated user
    current_user = request.current_user

    try:
        with get_db_session() as session:
            conn_repo = ConnectionRepository(session)
            connection = conn_repo.get_by_name(connection_name)

            if not connection:
                return jsonify({"error": "Connection not found"}), 404

            # Check if user has permission to access this connection
            if not current_user.is_admin and connection.created_by != current_user.username:
                return jsonify({"error": "You do not have permission to access this connection"}), 403

            return jsonify(
                {
                    "connection": {
                        "name": connection.name,
                        "created_at": connection.created_at.isoformat() if connection.created_at else None,
                        "created_by": connection.created_by,
                        "guacamole_connection_id": connection.guacamole_connection_id,
                        "persistent_home": connection.persistent_home,
                        "is_stopped": connection.is_stopped,
                        "desktop_configuration_id": connection.desktop_configuration_id,
                        "desktop_configuration_name": connection.desktop_configuration.name
                        if connection.desktop_configuration
                        else None,
                    }
                }
            ), HTTPStatus.OK
    except Exception as e:
        logging.error("Error getting connection: %s", str(e))
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@connections_bp.route("/direct-connect/<string:connection_id>", methods=["GET"])
@token_required
def direct_connect(connection_id: str):
    """Get the Guacamole auth URL for a direct connection.

    This endpoint:
    1. Retrieves the connection information
    2. Generates a properly formatted, signed, and encrypted JSON auth token
    3. Returns the auth URL for the client to redirect to

    Args:
        connection_id: The ID of the connection to access

    Returns:
        JSON with the auth URL for the Guacamole connection
    """
    try:
        # Get authenticated user
        current_user = request.current_user

        with get_db_session() as session:
            conn_repo = ConnectionRepository(session)
            connection = conn_repo.get_by_id(connection_id)

            if not connection:
                return jsonify({"error": "Connection not found"}), HTTPStatus.NOT_FOUND

            # Check if user has permission to access this connection
            if not current_user.is_admin and connection.created_by != current_user.username:
                return jsonify({"error": "You do not have permission to access this connection"}), HTTPStatus.FORBIDDEN

            # Get the Guacamole connection ID
            guacamole_connection_id = connection.guacamole_connection_id
            if not guacamole_connection_id:
                return jsonify({"error": "No Guacamole connection ID found"}), HTTPStatus.NOT_FOUND

            # Get Guacamole client
            guacamole_client = client_factory.get_guacamole_client()

            # Get auth token for direct connection
            token = guacamole_client.login()

            # Verify the connection exists in Guacamole
            connection_exists = guacamole_client.check_connection_exists(token, guacamole_connection_id)
            if not connection_exists:
                return jsonify({"error": "Guacamole connection does not exist"}), HTTPStatus.NOT_FOUND

            # Generate auth token directly for this specific connection
            settings = get_settings()
            guacamole_json_auth = GuacamoleJsonAuth()
            guacamole_external_url = settings.EXTERNAL_GUACAMOLE_URL.rstrip("/")
            if not guacamole_external_url:
                guacamole_external_url = "http://localhost:8080/guacamole"

            connection_params = guacamole_client.get_connection_params(token, guacamole_connection_id)

            token = guacamole_json_auth.generate_auth_data(
                username=current_user.username + "-tmp" + uuid.uuid4().hex,
                connections={
                    connection.name + "-direct": {
                        "protocol": "vnc",
                        "parameters": connection_params,
                    }
                },
                expires_in_ms=3600000,
            )  # 1 hour

            token = guacamole_client.json_auth_login(token)

            direct_url = f"{guacamole_external_url}/#/?token={token}"

            # Return the auth URL in the response
            return jsonify(
                {
                    "auth_url": direct_url,
                    "connection_id": connection_id,
                    "connection_name": connection.name,
                    "guacamole_connection_id": guacamole_connection_id,
                }
            ), HTTPStatus.OK
    except Exception as e:
        logging.error("Error generating connection auth URL: %s", str(e))
        return (
            jsonify({"error": "Internal server error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@connections_bp.route("/guacamole-dashboard", methods=["GET"])
@token_required
def guacamole_dashboard():
    """Get the authentication URL for the Guacamole dashboard.

    This endpoint:
    1. Gets the current authenticated user
    2. Generates a properly formatted, signed, and encrypted JSON auth token
    3. Returns the auth URL for the Guacamole dashboard

    Returns:
        JSON with the auth URL for the Guacamole dashboard
    """
    try:
        # Get authenticated user
        current_user = request.current_user

        # Initialize the JSON auth utility
        guacamole_json_auth = GuacamoleJsonAuth()
        guacamole_client = client_factory.get_guacamole_client()
        # Generate auth token (with empty connections as we're just accessing the dashboard)
        token = guacamole_json_auth.generate_auth_data(
            username=current_user.username,
            connections={},  # Empty connections as we're just accessing the dashboard
            expires_in_ms=3600000,  # 1 hour
        )
        token = guacamole_client.json_auth_login(token)

        # Construct the URL
        settings = get_settings()
        guacamole_external_url = settings.EXTERNAL_GUACAMOLE_URL.rstrip("/")
        if not guacamole_external_url:
            guacamole_external_url = "http://localhost:8080/guacamole"

        auth_url = f"{guacamole_external_url}/#/?token={token}"

        # Return the auth URL in the response
        return jsonify(
            {
                "auth_url": auth_url,
                "username": current_user.username,
            }
        ), HTTPStatus.OK

    except Exception as e:
        logging.error("Error generating Guacamole dashboard auth URL: %s", str(e))
        return (
            jsonify({"error": "Internal server error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@connections_bp.route("/resume", methods=["POST"])
@token_required
def resume_connection() -> tuple[dict[str, Any], int]:
    """Resume a previously deleted connection.

    This endpoint brings back a stopped desktop connection by:
    1. Validating the connection exists and is stopped
    2. Creating a new Rancher deployment
    3. Updating the connection status in the database

    Returns:
        Tuple[Dict[str, Any], int]: A tuple containing:
            - Dict with connection details or error message
            - HTTP status code
    """
    logging.info("=== Received request to /resume ===")
    logging.info("Request path: %s", request.path)
    logging.info("Request method: %s", request.method)
    logging.info("Request headers: %s", request.headers)

    current_user = request.current_user
    try:
        with get_db_session() as session:
            # Extract connection name from request
            data = request.get_json()
            if not data or "name" not in data:
                return (
                    jsonify({"error": "Missing required field: name"}),
                    HTTPStatus.BAD_REQUEST,
                )

            connection_name = data["name"]
            logging.info("Resuming connection: %s", connection_name)

            # Get connection from database
            conn_repo = ConnectionRepository(session)
            connection = conn_repo.get_by_name(connection_name)
            if not connection:
                return (
                    jsonify({"error": f"Stopped connection {connection_name} not found"}),
                    HTTPStatus.NOT_FOUND,
                )

            # Check if user has permission to resume this connection
            if not current_user.is_admin and connection.created_by != current_user.username:
                return (
                    jsonify({"error": "You do not have permission to resume this connection"}),
                    HTTPStatus.FORBIDDEN,
                )

            # Generate new VNC password
            vnc_password = generate_random_string(32)
            logging.debug("Generated VNC password")

            # Create Rancher API client
            settings = get_settings()
            rancher_client = client_factory.get_rancher_client()
            logging.debug("Created Rancher client")

            external_pvc = connection.pvcs[0].name if connection.pvcs else None
            config = connection.desktop_configuration

            # Create desktop values with CPU and RAM from configuration
            desktop_values = DesktopValues(
                desktop=config.image,
                name=connection_name,
                vnc_password=vnc_password,
                mincpu=config.min_cpu,
                maxcpu=config.max_cpu,
                minram=config.min_ram,
                maxram=config.max_ram,
                external_pvc=external_pvc,  # Set external PVC if found
            )

            # Configure storage with persistent_home setting
            desktop_values.storage.persistenthome = connection.persistent_home

            # Install Helm chart
            logging.info("Installing Helm chart for %s", connection_name)
            rancher_client.install(connection_name, desktop_values)
            logging.info("Helm chart installation completed")

            # Check if VNC server is ready
            logging.info("Checking if VNC server is ready for %s", connection_name)
            vnc_ready = rancher_client.check_vnc_ready(connection_name)
            status = "ready" if vnc_ready else "provisioning"
            logging.info("VNC server ready status for %s: %s", connection_name, status)

            # Get Guacamole client from factory
            guacamole_client = client_factory.get_guacamole_client()

            try:
                # Create Guacamole connection
                # First get a Guacamole token
                token = guacamole_client.login()
                # Ensure admins group exists
                guacamole_client.ensure_group(token, "admins")

                # Get settings here to ensure it's in scope
                settings = get_settings()

                # Use correct hostname format
                target_host = f"{settings.NAMESPACE}-{connection_name}.dyn.cloud.e-infra.cz"

                guacamole_connection_id = guacamole_client.create_connection(
                    token,
                    connection_name,
                    target_host,
                    vnc_password,
                )
                logging.info("Created Guacamole connection: %s", guacamole_connection_id)

                # Grant permission to admins group
                guacamole_client.grant_group_permission(token, "admins", guacamole_connection_id)
                logging.info("Granted permission to admins group")

                # Grant permission to user
                guacamole_client.grant_permission(token, current_user.username, guacamole_connection_id)
                logging.info("Granted permission to %s", current_user.username)
            except Exception as guac_error:
                # If Guacamole operations fail, clean up the Rancher deployment
                logging.error("Guacamole operation failed: %s", str(guac_error))
                try:
                    rancher_client.uninstall(connection_name)
                    logging.info("Cleaned up Rancher deployment after Guacamole error")
                except Exception as cleanup_error:
                    logging.error("Failed to clean up Rancher deployment: %s", str(cleanup_error))
                # Re-raise the original error
                raise guac_error

            # Update database to mark as active and update the new Guacamole connection ID
            conn_repo.update_connection(
                connection_name, {"is_stopped": False, "guacamole_connection_id": guacamole_connection_id}
            )

            updated_connection = conn_repo.get_by_name(connection_name)
            logging.info("Resumed connection in database: %s", connection_name)

            return (
                jsonify(
                    {
                        "message": f"Connection {connection_name} resumed successfully",
                        "connection": {
                            "name": updated_connection.name,
                            "id": updated_connection.id,
                            "created_at": (
                                updated_connection.created_at.isoformat() if updated_connection.created_at else None
                            ),
                            "created_by": updated_connection.created_by,
                            "guacamole_connection_id": updated_connection.guacamole_connection_id,
                            "status": status,
                            "persistent_home": updated_connection.persistent_home,
                        },
                    }
                ),
                HTTPStatus.OK,
            )
    except Exception as e:
        logging.error("Error in resume_connection: %s", str(e))
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@connections_bp.route("/permanent-delete", methods=["POST"])
@token_required
def permanent_delete() -> tuple[dict[str, Any], int]:
    """Permanently delete a connection and its associated PVC.

    This endpoint:
    1. Deletes the connection from the system
    2. Deletes the PVC with the name format [connection_name]-home

    For stopped connections with persistent home.

    Returns:
        tuple: A tuple containing:
            - Dict with results
            - HTTP status code
    """
    try:
        # Get authenticated user
        current_user = request.current_user

        # Extract connection name from request
        data = request.get_json()
        if not data or "name" not in data:
            return (
                jsonify({"error": "Missing required field: name"}),
                HTTPStatus.BAD_REQUEST,
            )

        connection_name = data["name"]
        logging.info("Permanently deleting connection: %s", connection_name)

        with get_db_session() as session:
            # Get connection from database
            conn_repo = ConnectionRepository(session)
            connection = conn_repo.get_by_name(connection_name)

            if not connection:
                return (
                    jsonify({"error": f"Connection {connection_name} not found"}),
                    HTTPStatus.NOT_FOUND,
                )

            # Check if connection is stopped
            if not connection.is_stopped:
                return (
                    jsonify({"error": f"Connection {connection_name} must be stopped first"}),
                    HTTPStatus.BAD_REQUEST,
                )

            # Check if user has permission to delete this connection
            if not current_user.is_admin and connection.created_by != current_user.username:
                return (
                    jsonify({"error": "You do not have permission to delete this connection"}),
                    HTTPStatus.FORBIDDEN,
                )

            # Delete the associated PVC if exists (format is [connection_name]-home)
            pvc_name = f"{connection_name}-home"
            rancher_client = client_factory.get_rancher_client()
            pvc_deleted = False

            try:
                # Try to get the PVC first to check if it exists
                rancher_client.get_pvc(name=pvc_name)

                # If no exception was raised, the PVC exists, so delete it
                rancher_client.delete_pvc(name=pvc_name)
                logging.info("Deleted PVC: %s", pvc_name)
                pvc_deleted = True
            except Exception as e:
                logging.warning("Failed to delete PVC %s: %s", pvc_name, str(e))

            # Delete connection from database
            conn_repo.delete_connection(connection.id)
            logging.info("Permanently deleted connection: %s", connection_name)

            # Return result
            message = f"Connection {connection_name} permanently deleted"
            if pvc_deleted:
                message += f" and PVC {pvc_name} removed"
            else:
                message += f" but failed to delete PVC {pvc_name}"

            return (
                jsonify({"message": message}),
                HTTPStatus.OK,
            )

    except Exception as e:
        logging.error("Error in permanent_delete: %s", str(e))
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR
