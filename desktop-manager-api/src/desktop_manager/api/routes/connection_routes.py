from http import HTTPStatus
import logging
from typing import Any, Dict, Tuple

from flask import Blueprint, jsonify, redirect, request

from desktop_manager.api.models.base import get_db
from desktop_manager.api.models.connection import Connection
from desktop_manager.clients.factory import client_factory
from desktop_manager.clients.guacamole import (
    create_guacamole_connection,
    delete_guacamole_connection,
    ensure_admins_group,
    grant_group_permission_on_connection,
    grant_user_permission_on_connection,
    guacamole_login,
)
from desktop_manager.config.settings import get_settings
from desktop_manager.core.auth import token_required
from desktop_manager.core.rancher import DesktopValues
from desktop_manager.utils.guacamole_json_auth import GuacamoleJsonAuth
from desktop_manager.utils.utils import (
    generate_random_string,
    generate_unique_connection_name,
    sanitize_name,
)


connections_bp = Blueprint("connections_bp", __name__)


@connections_bp.route("/scaleup", methods=["POST"])
@token_required
def scale_up() -> tuple[Dict[str, Any], int]:
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
        db_session = next(get_db())
        try:
            # Validate input data
            data = request.get_json()
            if not data or "name" not in data:
                return (
                    jsonify({"error": "Missing required field: name"}),
                    HTTPStatus.BAD_REQUEST,
                )

            # Sanitize and generate unique name
            base_name = sanitize_name(data["name"])
            logging.info("Sanitized base name: %s", base_name)
            name = generate_unique_connection_name(base_name, db_session)
            logging.info("Generated unique name: %s", name)

            # Get the current user
            current_user = request.current_user
            if current_user is None:
                logging.error("No authenticated user found")
                return (
                    jsonify({"error": "Authentication error: No user found"}),
                    HTTPStatus.UNAUTHORIZED,
                )

            logging.info("Current user: %s", current_user.username)

            # Generate VNC password
            vnc_password = generate_random_string(12)
            logging.info("Generated VNC password")

            # Create Rancher API client
            settings = get_settings()
            rancher_client = client_factory.get_rancher_client()
            logging.info("Created Rancher client")

            # Create desktop values
            desktop_values = DesktopValues(
                desktop=settings.DESKTOP_IMAGE, name=name, vnc_password=vnc_password
            )
            logging.info("Created desktop values")

            # Install Helm chart
            logging.info("Installing Helm chart for %s", name)
            rancher_client.install(name, desktop_values)
            logging.info("Helm chart installation completed")

            # Wait for VNC to be ready
            logging.info("Waiting for VNC to be ready...")
            vnc_ready = rancher_client.check_vnc_ready(name)
            if not vnc_ready:
                error_message = "VNC server failed to become ready"
                logging.error(error_message)
                # Attempt to clean up the failed deployment
                try:
                    rancher_client.uninstall(name)
                    logging.info("Cleaned up failed Helm chart for %s", name)
                except Exception as cleanup_error:
                    logging.error("Failed to clean up Helm chart: %s", str(cleanup_error))
                return (
                    jsonify({"error": error_message}),
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                )

            logging.info("VNC is ready")

            try:
                # Create Guacamole connection
                token = guacamole_login()
                # Ensure admins group exists
                ensure_admins_group(token)
                guacamole_connection_id = create_guacamole_connection(
                    token,
                    name,
                    # Use correct hostname format
                    f"{settings.NAMESPACE}-{name}.dyn.cloud.e-infra.cz",
                    vnc_password,
                )
                logging.info("Created Guacamole connection: %s", guacamole_connection_id)

                # Grant permission to admins group
                grant_group_permission_on_connection(token, "admins", guacamole_connection_id)
                logging.info("Granted permission to admins group")

                # Grant permission to user
                grant_user_permission_on_connection(
                    token, current_user.username, guacamole_connection_id
                )
                logging.info("Granted permission to %s", current_user.username)
            except Exception as e:
                # If Guacamole setup fails, clean up the Rancher deployment
                logging.error("Guacamole setup failed: %s", str(e))
                try:
                    rancher_client.uninstall(name)
                    logging.info("Cleaned up Rancher deployment after Guacamole failure")
                except Exception as cleanup_error:
                    logging.error("Failed to clean up Rancher deployment: %s", str(cleanup_error))
                return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR

            # Store in database
            connection = Connection(
                name=name,
                created_by=current_user.username,
                guacamole_connection_id=guacamole_connection_id,
                target_host=f"{settings.NAMESPACE}-{name}.dyn.cloud.e-infra.cz",
                target_port=5900,
                password=vnc_password,
                protocol="vnc",
            )
            db_session.add(connection)
            db_session.commit()
            logging.info("Stored connection in database: %s", name)

            return (
                jsonify(
                    {
                        "message": f"Connection {name} scaled up successfully",
                        "connection": {
                            "name": connection.name,
                            "id": connection.id,
                            "created_at": (
                                connection.created_at.isoformat() if connection.created_at else None
                            ),
                            "created_by": connection.created_by,
                            "guacamole_connection_id": connection.guacamole_connection_id,
                        },
                    }
                ),
                HTTPStatus.OK,
            )

        except Exception as e:
            db_session.rollback()
            logging.error("Database error: %s", str(e))
            raise
        finally:
            db_session.close()

    except Exception as e:
        logging.error("Error in scale_up: %s", str(e))
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@connections_bp.route("/scaledown", methods=["POST"])
@token_required
def scale_down() -> Tuple[Dict[str, Any], int]:
    """Scale down a desktop connection.

    This endpoint removes a desktop connection by:
    1. Uninstalling the Rancher deployment
    2. Deleting the Guacamole connection
    3. Removing the connection details from the database

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

        # Get database session
        db_session = next(get_db())
        try:
            # Get connection from database
            connection = db_session.query(Connection).filter_by(name=connection_name).first()
            if not connection:
                return (
                    jsonify({"error": f"Connection {connection_name} not found"}),
                    HTTPStatus.NOT_FOUND,
                )

            # Check if user has permission to delete this connection
            if not current_user.is_admin and connection.created_by != current_user.username:
                return (
                    jsonify({"error": "You do not have permission to delete this connection"}),
                    HTTPStatus.FORBIDDEN,
                )

            # Get Guacamole connection ID
            guacamole_connection_id = connection.guacamole_connection_id

            get_settings()

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
                # Continue to delete Guacamole connection and database entry

            # Delete Guacamole connection
            token = guacamole_login()
            try:
                delete_guacamole_connection(token, guacamole_connection_id)
                logging.info(
                    "Deleted Guacamole connection: %s",
                    guacamole_connection_id,
                )
                guacamole_delete_success = True
            except Exception as e:
                guacamole_delete_success = False
                logging.error("Failed to delete Guacamole connection: %s", str(e))
                # Continue to delete the database entry even if Guacamole deletion fails

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
                # Only delete the database entry if one of the operations succeeded
                db_session.delete(connection)
                db_session.commit()
                logging.info("Deleted database entry for connection: %s", connection_name)
                return (
                    jsonify(
                        {
                            "message": (
                                f"Connection {connection_name} scaled down with warnings: "
                                "Rancher deployment could not be removed"
                            )
                        }
                    ),
                    HTTPStatus.OK,
                )
            elif not guacamole_delete_success:
                # Only delete the database entry if one of the operations succeeded
                db_session.delete(connection)
                db_session.commit()
                logging.info("Deleted database entry for connection: %s", connection_name)
                return (
                    jsonify(
                        {
                            "message": (
                                f"Connection {connection_name} scaled down with warnings: "
                                "Guacamole connection could not be removed"
                            )
                        }
                    ),
                    HTTPStatus.OK,
                )
            else:
                # Delete database entry if all operations succeeded
                db_session.delete(connection)
                db_session.commit()
                logging.info("Deleted database entry for connection: %s", connection_name)
                return (
                    jsonify({"message": f"Connection {connection_name} scaled down successfully"}),
                    HTTPStatus.OK,
                )

        except Exception as e:
            db_session.rollback()
            logging.error("Database error in scale_down: %s", str(e))
            raise
        finally:
            db_session.close()

    except Exception as e:
        logging.error("Error in scale_down: %s", str(e))
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@connections_bp.route("/list", methods=["GET"])
@token_required
def list_connections() -> Tuple[Dict[str, Any], int]:
    """List all connections for the current user.

    This endpoint retrieves all connections from the database
    and includes a single sign-on URL for each connection.

    For admin users, all connections are returned.
    For non-admin users, only connections created by the user are returned.

    Returns:
        tuple: A tuple containing:
            - Dict with list of connections
            - HTTP status code
    """
    try:
        # Get authenticated user
        current_user = request.current_user

        # Get database session
        db_session = next(get_db())

        try:
            # Prepare the JSON auth utility
            guacamole_json_auth = GuacamoleJsonAuth()
            settings = get_settings()

            # Get connections from database - filter by user if not admin
            if current_user.is_admin:
                connections = db_session.query(Connection).all()
            else:
                connections = (
                    db_session.query(Connection)
                    .filter(Connection.created_by == current_user.username)
                    .all()
                )

            result = []

            for connection in connections:
                # Format connection parameters for JSON auth
                connection_info = {
                    "protocol": "vnc",
                    "parameters": {
                        "hostname": connection.target_host,
                        "port": str(connection.target_port),
                        "password": connection.password,
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
                    connections={connection.name: connection_info},
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
                        "id": connection.id,
                        "name": connection.name,
                        "target_host": connection.target_host,
                        "target_port": connection.target_port,
                        "created_at": (
                            connection.created_at.isoformat() if connection.created_at else None
                        ),
                        "created_by": connection.created_by,
                        "guacamole_connection_id": connection.guacamole_connection_id,
                        "auth_url": auth_url,
                    }
                )

            return jsonify({"connections": result}), HTTPStatus.OK

        finally:
            db_session.close()

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

    db_session = next(get_db())
    try:
        connection = db_session.query(Connection).filter_by(name=connection_name).first()
        if not connection:
            return jsonify({"error": "Connection not found"}), 404

        # Check if user has permission to access this connection
        if not current_user.is_admin and connection.created_by != current_user.username:
            return jsonify({"error": "You do not have permission to access this connection"}), 403

        return (
            jsonify(
                {
                    "connection": {
                        "name": connection.name,
                        "created_at": connection.created_at.isoformat(),
                        "created_by": connection.created_by,
                        "guacamole_connection_id": connection.guacamole_connection_id,
                    }
                }
            ),
            200,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db_session.close()


@connections_bp.route("/auth/<connection_id>", methods=["GET"])
@token_required
def get_connection_auth(connection_id: str) -> Tuple[Dict[str, Any], int]:
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

        # Get database session
        db_session = next(get_db())

        try:
            # Get connection from database
            connection = (
                db_session.query(Connection)
                .filter(Connection.guacamole_connection_id == connection_id)
                .first()
            )

            if not connection:
                return (
                    jsonify({"error": f"Connection with ID {connection_id} not found"}),
                    HTTPStatus.NOT_FOUND,
                )

            # Check if user has permission to access this connection
            if not current_user.is_admin and connection.created_by != current_user.username:
                return (
                    jsonify({"error": "You do not have permission to access this connection"}),
                    HTTPStatus.FORBIDDEN,
                )

            # Prepare the JSON auth utility
            guacamole_json_auth = GuacamoleJsonAuth()
            settings = get_settings()

            # Format connection parameters for JSON auth
            connection_info = {
                "protocol": "vnc",
                "parameters": {
                    "hostname": connection.target_host,
                    "port": str(connection.target_port),
                    "password": connection.password,
                    "enable-audio": "true",
                    "color-depth": "24",
                    "cursor": "local",
                    "swap-red-blue": "false",
                    "read-only": "false",
                },
            }

            # Format for Guacamole JSON auth
            connections = {connection.name: connection_info}

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
                        "connection_name": connection.name,
                        "auth_url": auth_url,
                    }
                ),
                HTTPStatus.OK,
            )

        finally:
            db_session.close()

    except Exception as e:
        logging.error("Error generating connection auth: %s", str(e))
        return (
            jsonify({"error": "Internal server error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@connections_bp.route("/direct-connect/<string:connection_id>", methods=["GET"])
@token_required
def direct_connect(connection_id: str):
    """Directly connect to a Guacamole connection via a redirect.

    This endpoint:
    1. Retrieves the connection information
    2. Generates a properly formatted, signed, and encrypted JSON auth token
    3. Redirects the user to the Guacamole connection

    Args:
        connection_id: The ID of the connection to access

    Returns:
        A redirect to the Guacamole connection with proper authentication
    """
    try:
        # Get authenticated user
        current_user = request.current_user

        # Get database session
        db_session = next(get_db())

        try:
            # Get connection details
            connection = db_session.query(Connection).filter(Connection.id == connection_id).first()
            if not connection:
                return jsonify({"error": "Connection not found"}), HTTPStatus.NOT_FOUND

            # Initialize the JSON auth utility
            guacamole_json_auth = GuacamoleJsonAuth()

            # Format connection parameters for JSON auth
            connection_info = {
                "protocol": "vnc",
                "parameters": {
                    "hostname": connection.target_host,
                    "port": str(connection.target_port),
                    "password": connection.password,
                    "enable-audio": "true",
                    "color-depth": "24",
                    "cursor": "local",
                    "swap-red-blue": "false",
                    "read-only": "false",
                },
            }

            # Format for Guacamole JSON auth
            connections = {connection.name: connection_info}

            # Generate auth token
            token = guacamole_json_auth.generate_auth_data(
                username=current_user.username,
                connections=connections,
                expires_in_ms=1800000,  # 30 minutes
            )

            # Construct the URL
            settings = get_settings()
            # Directly use the external Guacamole URL for client use
            guacamole_external_url = settings.EXTERNAL_GUACAMOLE_URL.rstrip("/")
            if not guacamole_external_url:
                guacamole_external_url = "http://localhost:8080/guacamole"

            # The URL should include the "data" parameter with the token
            import urllib.parse

            encoded_token = urllib.parse.quote_plus(token)
            auth_url = f"{guacamole_external_url}/#/?data={encoded_token}"

            # Redirect to the connection URL
            return redirect(auth_url)

        finally:
            db_session.close()

    except Exception as e:
        logging.error("Error redirecting to connection: %s", str(e))
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

        # Get database session
        db_session = next(get_db())

        try:
            # Get connection from database
            connection = db_session.query(Connection).filter_by(id=connection_id).first()
            if not connection:
                return (
                    jsonify({"error": f"Connection with ID {connection_id} not found"}),
                    HTTPStatus.NOT_FOUND,
                )

            # Check if user has permission to access this connection
            if not current_user.is_admin and connection.created_by != current_user.username:
                return (
                    jsonify({"error": "You do not have permission to access this connection"}),
                    HTTPStatus.FORBIDDEN,
                )

            # Get Guacamole connection ID
            guacamole_connection_id = connection.guacamole_connection_id

            # Generate auth URL
            settings = get_settings()
            guacamole_json_auth = GuacamoleJsonAuth(
                secret_key=settings.GUACAMOLE_SECRET_KEY,
                guacamole_url=settings.GUACAMOLE_URL,
            )
            auth_data = guacamole_json_auth.generate_auth_data(
                username=current_user.username,
                connection_id=guacamole_connection_id,
            )

            return (
                jsonify(
                    {
                        "connection_id": connection_id,
                        "connection_name": connection.name,
                        "auth_url": auth_data,
                    }
                ),
                HTTPStatus.OK,
            )

        except Exception as e:
            db_session.rollback()
            logging.error("Database error in get_connection_auth: %s", str(e))
            raise
        finally:
            db_session.close()

    except Exception as e:
        logging.error("Error generating connection auth: %s", str(e))
        return (
            jsonify({"error": "Internal server error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )
