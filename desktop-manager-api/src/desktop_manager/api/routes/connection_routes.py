from http import HTTPStatus
import logging
import re
from typing import Any

from flask import Blueprint, jsonify, request

from desktop_manager.clients.factory import client_factory
from desktop_manager.clients.rancher import DesktopValues
from desktop_manager.config.settings import get_settings
from desktop_manager.core.auth import token_required
from desktop_manager.utils.guacamole_json_auth import GuacamoleJsonAuth
from desktop_manager.utils.utils import (
    generate_random_string,
    generate_unique_connection_name,
    sanitize_name,
)


connections_bp = Blueprint("connections_bp", __name__)


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
        # Get database client
        db_client = client_factory.get_database_client()

        try:
            # Validate input data
            data = request.get_json()
            if not data or "name" not in data:
                return (
                    jsonify({"error": "Missing required field: name"}),
                    HTTPStatus.BAD_REQUEST,
                )

            # Validate name against the required pattern
            name_pattern = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")
            if not name_pattern.match(data["name"]):
                return (
                    jsonify(
                        {
                            "error": "Connection name must start and end with an alphanumeric character "
                            "and contain only lowercase letters, numbers, and hyphens"
                        }
                    ),
                    HTTPStatus.BAD_REQUEST,
                )

            # Check if name is too long (max 12 characters)
            if len(data["name"]) > 12:
                return (
                    jsonify({"error": "Connection name is too long. Maximum length is 12 characters."}),
                    HTTPStatus.BAD_REQUEST,
                )

            # Get persistent_home parameter (default to True if not provided)
            persistent_home = data.get("persistent_home", True)

            # Get external_pvc parameter (default to None if not provided)
            external_pvc = data.get("external_pvc")

            # If external_pvc is provided, verify it exists and user has access
            if external_pvc:
                logging.info("External PVC specified: %s", external_pvc)
                try:
                    # Get PVC from database
                    pvc_query = """
                    SELECT sp.id, sp.name, sp.namespace, sp.created_by, sp.is_public
                    FROM storage_pvcs sp
                    WHERE sp.name = :name
                    """
                    pvc_result, pvc_count = db_client.execute_query(
                        pvc_query,
                        {"name": external_pvc},
                    )

                    if pvc_count == 0:
                        return (
                            jsonify({"error": f"PVC '{external_pvc}' not found"}),
                            HTTPStatus.NOT_FOUND,
                        )

                    # Check if user has permission to use this PVC
                    pvc = pvc_result[0]

                    # Admins have access to all PVCs
                    if request.current_user.is_admin:
                        logging.info("Admin user - access granted to PVC")
                    # Public PVCs are accessible to all users
                    elif pvc["is_public"]:
                        logging.info("Public PVC - access granted to all users")
                    else:
                        # Check access table
                        access_query = """
                        SELECT id
                        FROM storage_pvc_access
                        WHERE pvc_id = :pvc_id AND username = :username
                        """
                        _, access_count = db_client.execute_query(
                            access_query,
                            {"pvc_id": pvc["id"], "username": request.current_user.username},
                        )

                        if access_count == 0:
                            return (
                                jsonify({"error": "You do not have permission to use this PVC"}),
                                HTTPStatus.FORBIDDEN,
                            )
                        logging.info("User has explicit access to PVC from access table")

                    logging.info("PVC access verified")
                except Exception as e:
                    logging.error("Error verifying PVC: %s", str(e))
                    return (
                        jsonify({"error": f"Error verifying PVC: {e!s}"}),
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                    )

            # Get desktop_configuration_id (default to 1 if not provided)
            desktop_configuration_id = data.get("desktop_configuration_id")

            # If desktop_configuration_id is provided, verify it exists and user has access
            if desktop_configuration_id:
                # Different queries for admin vs regular users
                if request.current_user.is_admin:
                    # Admins can access any configuration
                    config_query = """
                    SELECT *
                    FROM desktop_configurations
                    WHERE id = :config_id
                    """
                    config_result, config_count = db_client.execute_query(
                        config_query,
                        {
                            "config_id": desktop_configuration_id,
                        },
                    )
                else:
                    config_query = """
                    SELECT dc.*
                    FROM desktop_configurations dc
                    LEFT JOIN desktop_configuration_access dca
                        ON dc.id = dca.desktop_configuration_id AND dca.username = :username
                    WHERE dc.id = :config_id AND (dc.is_public = TRUE OR dca.username IS NOT NULL)
                    """
                    config_result, config_count = db_client.execute_query(
                        config_query,
                        {
                            "config_id": desktop_configuration_id,
                            "username": request.current_user.username,
                        },
                    )

                if config_count == 0:
                    return (
                        jsonify({"error": "Desktop configuration not found or access denied"}),
                        HTTPStatus.NOT_FOUND,
                    )

                desktop_image = config_result[0]["image"]
                min_cpu = config_result[0]["min_cpu"]
                max_cpu = config_result[0]["max_cpu"]
                min_ram = config_result[0]["min_ram"]
                max_ram = config_result[0]["max_ram"]
            else:
                # Use default configuration (ID 1)
                config_query = """
                SELECT id, image, min_cpu, max_cpu, min_ram, max_ram FROM desktop_configurations WHERE id = 1
                """
                config_result, config_count = db_client.execute_query(config_query)

                if config_count == 0:
                    # If no default configuration exists, use the hardcoded one
                    settings = get_settings()
                    desktop_image = settings.DESKTOP_IMAGE
                    desktop_configuration_id = None
                    min_cpu = 1
                    max_cpu = 4
                    min_ram = "4096Mi"
                    max_ram = "16384Mi"
                else:
                    desktop_image = config_result[0]["image"]
                    desktop_configuration_id = config_result[0]["id"]
                    min_cpu = config_result[0]["min_cpu"]
                    max_cpu = config_result[0]["max_cpu"]
                    min_ram = config_result[0]["min_ram"]
                    max_ram = config_result[0]["max_ram"]

            # Sanitize and generate unique name
            base_name = sanitize_name(data["name"])
            logging.info("Sanitized base name: %s", base_name)

            # Check if name already exists
            query = "SELECT name FROM connections WHERE name LIKE :name_pattern"
            existing_names, _ = db_client.execute_query(query, {"name_pattern": f"{base_name}%"})

            # Get the current user
            current_user = request.current_user
            if current_user is None:
                logging.error("No authenticated user found")
                return (
                    jsonify({"error": "Authentication error: No user found"}),
                    HTTPStatus.UNAUTHORIZED,
                )

            logging.info("Current user: %s", current_user.username)

            # Generate unique name with UUID instead of username
            name = generate_unique_connection_name(base_name)
            logging.info("Generated unique name: %s", name)

            # Generate VNC password
            vnc_password = generate_random_string(12)
            logging.info("Generated VNC password")

            # Create Rancher API client
            rancher_client = client_factory.get_rancher_client()
            logging.info("Created Rancher client")

            # Create desktop values
            desktop_values = DesktopValues(
                desktop=desktop_image,
                name=name,
                vnc_password=vnc_password,
                mincpu=min_cpu,
                maxcpu=max_cpu,
                minram=min_ram,
                maxram=max_ram,
                external_pvc=external_pvc,  # Set external PVC if provided
            )

            # Configure storage with persistent_home setting
            desktop_values.storage.persistenthome = persistent_home

            # Enable storage if external PVC is provided
            if external_pvc:
                desktop_values.storage.enable = True
                logging.info("Enabled storage with external PVC: %s", external_pvc)

            logging.info("Created desktop values with persistent_home=%s", persistent_home)

            # Install Helm chart
            logging.info("Installing Helm chart for %s", name)
            rancher_client.install(name, desktop_values)
            logging.info("Helm chart installation completed")

            # Check if VNC server is ready
            logging.info("Checking if VNC server is ready for %s", name)
            vnc_ready = rancher_client.check_vnc_ready(name)
            status = "ready" if vnc_ready else "provisioning"
            logging.info("VNC server ready status for %s: %s", name, status)

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
                logging.info("Granted permission to admins group")

                # Grant permission to user
                guacamole_client.grant_permission(token, current_user.username, guacamole_connection_id)
                logging.info("Granted permission to %s", current_user.username)
            except Exception as guac_error:
                # If Guacamole operations fail, clean up the Rancher deployment
                logging.error("Guacamole operation failed: %s", str(guac_error))
                try:
                    rancher_client.uninstall(name)
                    logging.info("Cleaned up Rancher deployment after Guacamole error")
                except Exception as cleanup_error:
                    logging.error("Failed to clean up Rancher deployment: %s", str(cleanup_error))
                # Re-raise the original error
                raise guac_error

            # Save connection to database
            connection_id_query = """
            INSERT INTO connections (
                name,
                created_by,
                guacamole_connection_id,
                is_stopped,
                persistent_home,
                desktop_configuration_id
            )
            VALUES (
                :name,
                :created_by,
                :guacamole_connection_id,
                FALSE,
                :persistent_home,
                :desktop_configuration_id
            )
            RETURNING id
            """

            conn_results, _ = db_client.execute_query(
                connection_id_query,
                {
                    "name": name,
                    "created_by": current_user.username,
                    "guacamole_connection_id": guacamole_connection_id,
                    "persistent_home": persistent_home,
                    "desktop_configuration_id": desktop_configuration_id,
                },
            )

            connection_id = conn_results[0]["id"]
            logging.info("Created connection with ID: %s", connection_id)

            # If external PVC was used, map it to the connection
            if external_pvc:
                try:
                    # Get PVC ID
                    pvc_query = "SELECT id FROM storage_pvcs WHERE name = :name"
                    pvc_result, _ = db_client.execute_query(pvc_query, {"name": external_pvc})
                    pvc_id = pvc_result[0]["id"]

                    # Map connection to PVC
                    mapping_id = db_client.map_connection_to_pvc(connection_id, pvc_id)
                    logging.info(
                        "Mapped connection %s to PVC %s with mapping ID %s",
                        connection_id,
                        pvc_id,
                        mapping_id,
                    )
                except Exception as e:
                    logging.error("Error mapping connection to PVC: %s", str(e))
                    # Continue even if mapping fails

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

            return (
                jsonify(response_data),
                HTTPStatus.OK,
            )

        except Exception as e:
            logging.error("Database error: %s", str(e))
            raise

    except Exception as e:
        logging.error("Error in scale_up: %s", str(e))
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


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
    try:
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
        if current_user is None:
            logging.error("No authenticated user found")
            return (
                jsonify({"error": "Authentication error: No user found"}),
                HTTPStatus.UNAUTHORIZED,
            )

        logging.info("Current user: %s", current_user.username)

        # Get database client
        db_client = client_factory.get_database_client()

        try:
            # Get connection from database
            query = """
            SELECT * FROM connections
            WHERE name = :connection_name
            """
            result, count = db_client.execute_query(query, {"connection_name": connection_name})

            if count == 0:
                return (
                    jsonify({"error": f"Connection {connection_name} not found"}),
                    HTTPStatus.NOT_FOUND,
                )

            connection = result[0]

            # Check if user has permission to delete this connection
            if not current_user.is_admin and connection["created_by"] != current_user.username:
                return (
                    jsonify({"error": "You do not have permission to delete this connection"}),
                    HTTPStatus.FORBIDDEN,
                )

            # Get Guacamole connection ID
            guacamole_connection_id = connection["guacamole_connection_id"]
            persistent_home = connection.get("persistent_home", True)

            get_settings()

            # Uninstall the Rancher deployment
            try:
                # Create Rancher API client
                rancher_client = client_factory.get_rancher_client()
                logging.info("Created Rancher client for uninstallation")

                # Uninstall the Helm chart
                rancher_client.uninstall(connection["name"])
                logging.info("Uninstalled Helm chart for %s", connection["name"])
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
                logging.info(
                    "Deleted Guacamole connection: %s",
                    guacamole_connection_id,
                )
                guacamole_delete_success = True
            except Exception as e:
                guacamole_delete_success = False
                logging.error("Failed to delete Guacamole connection: %s", str(e))
                # Continue to update the database entry even if Guacamole deletion fails

            # Check if we should soft delete or hard delete
            if persistent_home:
                # Soft delete - mark as stopped in the database
                update_query = """
                UPDATE connections
                SET is_stopped = TRUE
                WHERE name = :connection_name
                """
                db_client.execute_query(update_query, {"connection_name": connection_name})
                logging.info("Marked connection as stopped: %s", connection_name)

                message = f"Connection {connection_name} scaled down and preserved for future resumption"
            else:
                # Hard delete - remove from database
                delete_query = """
                DELETE FROM connections                "created_by": pvc.created_by,
                "status": pvc.status,
                "last_updated": pvc.last_updated,
            })
            pvc_model = StoragePVCModel.model_validate(pvc)
                WHERE name = :connection_name
                """
                db_client.execute_query(delete_query, {"connection_name": connection_name})
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
            logging.error("Database error in scale_down: %s", str(e))
            raise

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

        # Get database client
        db_client = client_factory.get_database_client()

        try:
            # Prepare the JSON auth utility
            guacamole_json_auth = GuacamoleJsonAuth()
            settings = get_settings()

            # Get connections from database - filter by user if not admin
            if current_user.is_admin:
                logging.debug("Listing connections for admin user")
                if creator_filter:
                    logging.debug("Filtering connections by creator: %s", creator_filter)
                    query = """
                    SELECT c.*, dc.name as desktop_configuration_name
                    FROM connections c
                    LEFT JOIN desktop_configurations dc ON c.desktop_configuration_id = dc.id
                    WHERE c.created_by = :username
                    """
                    connections, _ = db_client.execute_query(query, {"username": creator_filter})
                else:
                    query = """
                    SELECT c.*, dc.name as desktop_configuration_name
                    FROM connections c
                    LEFT JOIN desktop_configurations dc ON c.desktop_configuration_id = dc.id
                    """
                    connections, _ = db_client.execute_query(query)
            else:
                logging.debug("Listing connections for non-admin user")
                query = """
                SELECT c.*, dc.name as desktop_configuration_name
                FROM connections c
                LEFT JOIN desktop_configurations dc ON c.desktop_configuration_id = dc.id
                WHERE c.created_by = :username
                """
                connections, _ = db_client.execute_query(query, {"username": current_user.username})

            result = []

            for connection in connections:
                # Construct target host from connection name
                target_host = f"{settings.NAMESPACE}-{connection['name']}.dyn.cloud.e-infra.cz"

                # Format connection parameters for JSON auth
                connection_info = {
                    "protocol": "vnc",
                    "parameters": {
                        "hostname": target_host,
                        "port": "5900",  # Fixed VNC port
                        "password": connection.get("password", ""),  # Password is in Guacamole, not in our DB
                        "enable-audio": "true",
                        "color-depth": "24",
                        "cursor": "local",
                        "swap-red-blue": "false",
                        "read-only": "false",
                    },
                }

                # Generate auth token for this specific connection
                token = guacamole_json_auth.generate_auth_data(
                    username=current_user.username,
                    connections={connection["name"]: connection_info},
                    expires_in_ms=1800000,  # 30 minutes
                )

                # Construct the URL
                external_guacamole_url = settings.EXTERNAL_GUACAMOLE_URL.rstrip("/")
                import urllib.parse

                encoded_token = urllib.parse.quote_plus(token)
                auth_url = f"{external_guacamole_url}/#/?data={encoded_token}"

                # Add to result
                result.append(
                    {
                        "id": connection["id"],
                        "name": connection["name"],
                        "created_at": (connection["created_at"].isoformat() if connection["created_at"] else None),
                        "created_by": connection["created_by"],
                        "guacamole_connection_id": connection["guacamole_connection_id"],
                        "auth_url": auth_url,
                        "persistent_home": connection.get("persistent_home", True),
                        "is_stopped": connection.get("is_stopped", False),
                        "desktop_configuration_id": connection.get("desktop_configuration_id"),
                        "desktop_configuration_name": connection.get("desktop_configuration_name"),
                    }
                )

            return jsonify({"connections": result}), HTTPStatus.OK

        except Exception as e:
            logging.error("Database error: %s", str(e))
            raise

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

    # Get database client
    db_client = client_factory.get_database_client()

    try:
        query = """
        SELECT c.*, dc.name as desktop_configuration_name
        FROM connections c
        LEFT JOIN desktop_configurations dc ON c.desktop_configuration_id = dc.id
        WHERE c.name = :connection_name
        """
        result, count = db_client.execute_query(query, {"connection_name": connection_name})

        if count == 0:
            return jsonify({"error": "Connection not found"}), 404

        connection = result[0]

        # Check if user has permission to access this connection
        if not current_user.is_admin and connection["created_by"] != current_user.username:
            return jsonify({"error": "You do not have permission to access this connection"}), 403

        return (
            jsonify(
                {
                    "connection": {
                        "name": connection["name"],
                        "created_at": connection["created_at"].isoformat() if connection["created_at"] else None,
                        "created_by": connection["created_by"],
                        "guacamole_connection_id": connection["guacamole_connection_id"],
                        "persistent_home": connection.get("persistent_home", True),
                        "is_stopped": connection.get("is_stopped", False),
                        "desktop_configuration_id": connection.get("desktop_configuration_id"),
                        "desktop_configuration_name": connection.get("desktop_configuration_name"),
                    }
                }
            ),
            200,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@connections_bp.route("/auth/<connection_id>", methods=["GET"])
@token_required
def get_connection_auth(connection_id: str) -> tuple[dict[str, Any], int]:
    """Generate a single sign-on URL for connecting to a Guacamole connection.

    This endpoint generates a single sign-on URL for connecting to a Guacamole
    connection. The URL includes a JSON Web Token (JWT) that authenticates
    the user with Guacamole.

    Args:
        connection_id: ID of the Guacamole connection

    Returns:
        tuple: A tuple containing:
            - Dict with connection details and auth URL
            - HTTP status code
    """
    try:
        # Get authenticated user
        current_user = request.current_user

        # Get database client
        db_client = client_factory.get_database_client()

        try:
            # Get connection from database
            query = """
            SELECT * FROM connections
            WHERE guacamole_connection_id = :connection_id
            """
            result, count = db_client.execute_query(query, {"connection_id": connection_id})

            if count == 0:
                return (
                    jsonify({"error": f"Connection with ID {connection_id} not found"}),
                    HTTPStatus.NOT_FOUND,
                )

            connection = result[0]

            # Check if user has permission to access this connection
            if not current_user.is_admin and connection["created_by"] != current_user.username:
                return (
                    jsonify({"error": "You do not have permission to access this connection"}),
                    HTTPStatus.FORBIDDEN,
                )

            # Prepare the JSON auth utility
            settings = get_settings()
            guacamole_json_auth = GuacamoleJsonAuth(
                secret_key=settings.GUACAMOLE_JSON_SECRET_KEY, guacamole_url=settings.GUACAMOLE_URL
            )

            # Construct hostname from connection name
            target_host = f"{settings.NAMESPACE}-{connection['name']}.dyn.cloud.e-infra.cz"

            # Format connection parameters for JSON auth
            connection_info = {
                "protocol": "vnc",
                "parameters": {
                    "hostname": target_host,
                    "port": "5900",  # Fixed VNC port
                    "password": connection.get("password", ""),  # Password is stored in Guacamole, not in our DB
                    "enable-audio": "true",
                    "color-depth": "24",
                    "cursor": "local",
                    "swap-red-blue": "false",
                    "read-only": "false",
                },
            }

            # Format for Guacamole JSON auth
            connections = {connection["name"]: connection_info}

            # Generate auth token
            token = guacamole_json_auth.generate_auth_data(
                username=current_user.username,
                connections=connections,
                expires_in_ms=1800000,  # 30 minutes
            )

            # Construct the URL
            guacamole_external_url = settings.EXTERNAL_GUACAMOLE_URL.rstrip("/")
            if not guacamole_external_url:
                guacamole_external_url = "http://localhost:8080/guacamole"

            # The URL should include the "data" parameter with the token
            import urllib.parse

            encoded_token = urllib.parse.quote_plus(token)
            auth_url = f"{guacamole_external_url}/#/?data={encoded_token}"

            # Return the connection URL
            return (
                jsonify(
                    {
                        "connection_id": connection_id,
                        "connection_name": connection["name"],
                        "auth_url": auth_url,
                    }
                ),
                HTTPStatus.OK,
            )

        except Exception as e:
            logging.error("Database error: %s", str(e))
            raise

    except Exception as e:
        logging.error("Error generating connection auth: %s", str(e))
        return (
            jsonify({"error": "Internal server error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


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

        # Get database client
        db_client = client_factory.get_database_client()

        try:
            # Get connection details
            query = """
            SELECT * FROM connections
            WHERE id = :connection_id
            """
            result, count = db_client.execute_query(query, {"connection_id": connection_id})

            if count == 0:
                return jsonify({"error": "Connection not found"}), HTTPStatus.NOT_FOUND

            connection = result[0]

            # Check if user has permission to access this connection
            if not current_user.is_admin and connection["created_by"] != current_user.username:
                return (
                    jsonify({"error": "You do not have permission to access this connection"}),
                    HTTPStatus.FORBIDDEN,
                )

            # Get the Guacamole connection ID
            guacamole_connection_id = connection.get("guacamole_connection_id")
            if not guacamole_connection_id:
                return jsonify({"error": "No Guacamole connection ID found"}), HTTPStatus.NOT_FOUND

            # Get Guacamole client
            guacamole_client = client_factory.get_guacamole_client()

            # Get auth token for direct connection
            token = guacamole_client.login()

            # Verify the connection exists in Guacamole
            connection_exists = guacamole_client.check_connection_exists(token, guacamole_connection_id)
            if not connection_exists:
                # Try to recreate the connection if it doesn't exist
                logging.warning(
                    "Guacamole connection %s not found, attempting to recreate",
                    guacamole_connection_id,
                )
                try:
                    settings = get_settings()
                    target_host = f"{settings.NAMESPACE}-{connection['name']}.dyn.cloud.e-infra.cz"

                    # We don't have the original VNC password stored in our database
                    # We'll need to create a new one and update the connection
                    vnc_password = generate_random_string(12)

                    # Create new connection in Guacamole
                    new_guacamole_connection_id = guacamole_client.create_connection(
                        token,
                        connection["name"],
                        target_host,
                        vnc_password,
                    )

                    # Update the connection in our database
                    update_query = """
                    UPDATE connections
                    SET guacamole_connection_id = :new_id
                    WHERE id = :connection_id
                    """
                    db_client.execute_query(
                        update_query,
                        {"new_id": new_guacamole_connection_id, "connection_id": connection_id},
                    )

                    # Grant permission to user
                    guacamole_client.grant_permission(token, current_user.username, new_guacamole_connection_id)

                    # Use the new connection ID
                    guacamole_connection_id = new_guacamole_connection_id
                    logging.info("Created new Guacamole connection: %s", guacamole_connection_id)
                except Exception as e:
                    logging.error("Failed to recreate Guacamole connection: %s", str(e))
                    return jsonify(
                        {"error": "Failed to recreate Guacamole connection"}
                    ), HTTPStatus.INTERNAL_SERVER_ERROR

            # Generate auth token directly for this specific connection
            settings = get_settings()

            # Use the Guacamole REST API auth token to direct to the specific connection
            auth_token = guacamole_client.get_auth_token(token)

            # Construct the URL to go directly to the connection
            guacamole_external_url = settings.EXTERNAL_GUACAMOLE_URL.rstrip("/")
            if not guacamole_external_url:
                guacamole_external_url = "http://localhost:8080/guacamole"

            # Format direct connection URL with the specific connection ID
            direct_url = f"{guacamole_external_url}/#/client/{guacamole_connection_id}?token={auth_token}"

            # Return the auth URL in the response
            return jsonify(
                {
                    "auth_url": direct_url,
                    "connection_id": connection_id,
                    "connection_name": connection["name"],
                    "guacamole_connection_id": guacamole_connection_id,
                }
            ), HTTPStatus.OK

        except Exception as e:
            logging.error("Database error: %s", str(e))
            raise

    except Exception as e:
        logging.error("Error generating connection auth URL: %s", str(e))
        return (
            jsonify({"error": "Internal server error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@connections_bp.route("/connect/<string:connection_id>", methods=["GET"])
@token_required
def get_connection_auth_url(connection_id: str):
    """Get authentication URL for a Guacamole connection.

    This endpoint:
    1. Retrieves the connection information
    2. Generates a properly formatted, signed, and encrypted JSON auth token
    3. Returns the auth URL for the client to use

    Args:
        connection_id: The ID of the connection to access

    Returns:
        JSON with connection details and auth URL
    """
    try:
        # Get authenticated user
        current_user = request.current_user

        # Get database client
        db_client = client_factory.get_database_client()

        try:
            # Get connection from database
            query = """
            SELECT * FROM connections
            WHERE id = :connection_id
            """
            result, count = db_client.execute_query(query, {"connection_id": connection_id})

            if count == 0:
                return (
                    jsonify({"error": f"Connection with ID {connection_id} not found"}),
                    HTTPStatus.NOT_FOUND,
                )

            connection = result[0]

            # Check if user has permission to access this connection
            if not current_user.is_admin and connection["created_by"] != current_user.username:
                return (
                    jsonify({"error": "You do not have permission to access this connection"}),
                    HTTPStatus.FORBIDDEN,
                )

            # Get Guacamole connection ID
            guacamole_connection_id = connection["guacamole_connection_id"]

            # Generate auth URL
            settings = get_settings()
            guacamole_json_auth = GuacamoleJsonAuth(
                secret_key=settings.GUACAMOLE_SECRET_KEY, guacamole_url=settings.GUACAMOLE_URL
            )
            auth_data = guacamole_json_auth.generate_auth_data(
                username=current_user.username,
                connection_id=guacamole_connection_id,
            )

            return (
                jsonify(
                    {
                        "connection_id": connection_id,
                        "connection_name": connection["name"],
                        "auth_url": auth_data,
                    }
                ),
                HTTPStatus.OK,
            )

        except Exception as e:
            logging.error("Database error in get_connection_auth: %s", str(e))
            raise

    except Exception as e:
        logging.error("Error generating connection auth: %s", str(e))
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

        # Generate auth token (with empty connections as we're just accessing the dashboard)
        token = guacamole_json_auth.generate_auth_data(
            username=current_user.username,
            connections={},  # Empty connections as we're just accessing the dashboard
            expires_in_ms=3600000,  # 1 hour
        )

        # Construct the URL
        settings = get_settings()
        guacamole_external_url = settings.EXTERNAL_GUACAMOLE_URL.rstrip("/")
        if not guacamole_external_url:
            guacamole_external_url = "http://localhost:8080/guacamole"

        # The URL should include the "data" parameter with the token
        import urllib.parse

        encoded_token = urllib.parse.quote_plus(token)
        auth_url = f"{guacamole_external_url}/#/?data={encoded_token}"

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
    if current_user is None:
        return (
            jsonify({"error": "Authentication error: No user found"}),
            HTTPStatus.UNAUTHORIZED,
        )

    try:
        # Extract connection name from request
        data = request.get_json()
        if not data or "name" not in data:
            return (
                jsonify({"error": "Missing required field: name"}),
                HTTPStatus.BAD_REQUEST,
            )

        connection_name = data["name"]
        logging.info("Resuming connection: %s", connection_name)

        # Get database client
        db_client = client_factory.get_database_client()

        try:
            # Get connection from database
            query = """
            SELECT c.*, dc.min_cpu, dc.max_cpu, dc.min_ram, dc.max_ram
            FROM connections c
            LEFT JOIN desktop_configurations dc ON c.desktop_configuration_id = dc.id
            WHERE c.name = :connection_name AND c.is_stopped = TRUE
            """
            result, count = db_client.execute_query(query, {"connection_name": connection_name})

            if count == 0:
                return (
                    jsonify({"error": f"Stopped connection {connection_name} not found"}),
                    HTTPStatus.NOT_FOUND,
                )

            connection = result[0]

            # Check if user has permission to resume this connection
            if not current_user.is_admin and connection["created_by"] != current_user.username:
                return (
                    jsonify({"error": "You do not have permission to resume this connection"}),
                    HTTPStatus.FORBIDDEN,
                )

            # Generate new VNC password
            vnc_password = generate_random_string(12)
            logging.info("Generated VNC password")

            # Create Rancher API client
            settings = get_settings()
            rancher_client = client_factory.get_rancher_client()
            logging.info("Created Rancher client")

            # Check if connection has an associated PVC
            pvc_query = """
            SELECT p.name
            FROM storage_pvcs p
            JOIN connection_pvcs cp ON p.id = cp.pvc_id
            WHERE cp.connection_id = :connection_id
            """
            pvc_result, pvc_count = db_client.execute_query(pvc_query, {"connection_id": connection["id"]})

            external_pvc = None
            if pvc_count > 0:
                external_pvc = pvc_result[0]["name"]
                logging.info("Found associated PVC: %s", external_pvc)

            # Create desktop values with CPU and RAM from configuration
            desktop_values = DesktopValues(
                desktop=settings.DESKTOP_IMAGE,
                name=connection_name,
                vnc_password=vnc_password,
                mincpu=connection.get("min_cpu", 1),
                maxcpu=connection.get("max_cpu", 4),
                minram=connection.get("min_ram", "4096Mi"),
                maxram=connection.get("max_ram", "16384Mi"),
                external_pvc=external_pvc,  # Set external PVC if found
            )

            # Configure storage with persistent_home setting
            desktop_values.storage.persistenthome = connection.get("persistent_home", True)

            # Enable storage if external PVC is used
            if external_pvc:
                desktop_values.storage.enable = True
                logging.info("Enabled storage with external PVC: %s", external_pvc)

            logging.info(
                "Created desktop values with persistent_home=%s",
                connection.get("persistent_home", True),
            )

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
            update_query = """
            UPDATE connections
            SET is_stopped = FALSE, guacamole_connection_id = :guacamole_connection_id
            WHERE name = :connection_name
            RETURNING id, name, created_at, created_by, guacamole_connection_id
            """

            update_data = {
                "connection_name": connection_name,
                "guacamole_connection_id": guacamole_connection_id,
            }

            result, _ = db_client.execute_query(update_query, update_data)
            updated_connection = result[0]
            logging.info("Resumed connection in database: %s", connection_name)

            return (
                jsonify(
                    {
                        "message": f"Connection {connection_name} resumed successfully",
                        "connection": {
                            "name": updated_connection["name"],
                            "id": updated_connection["id"],
                            "created_at": (
                                updated_connection["created_at"].isoformat()
                                if updated_connection["created_at"]
                                else None
                            ),
                            "created_by": updated_connection["created_by"],
                            "guacamole_connection_id": updated_connection["guacamole_connection_id"],
                            "status": status,
                            "persistent_home": connection.get("persistent_home", True),
                        },
                    }
                ),
                HTTPStatus.OK,
            )

        except Exception as e:
            logging.error("Database error in resume_connection: %s", str(e))
            raise

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

        # Get database client
        db_client = client_factory.get_database_client()

        try:
            # Get connection from database
            query = """
            SELECT * FROM connections
            WHERE name = :connection_name
            """
            result, count = db_client.execute_query(query, {"connection_name": connection_name})

            if count == 0:
                return (
                    jsonify({"error": f"Connection {connection_name} not found"}),
                    HTTPStatus.NOT_FOUND,
                )

            connection = result[0]

            # Check if connection is stopped
            if not connection.get("is_stopped", False):
                return (
                    jsonify({"error": f"Connection {connection_name} must be stopped first"}),
                    HTTPStatus.BAD_REQUEST,
                )

            # Check if user has permission to delete this connection
            if not current_user.is_admin and connection["created_by"] != current_user.username:
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
                # Continue with connection deletion even if PVC deletion fails

            # Delete connection from database
            db_client.delete_connection(connection_name)
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
            logging.error("Database error in permanent_delete: %s", str(e))
            raise

    except Exception as e:
        logging.error("Error in permanent_delete: %s", str(e))
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR
