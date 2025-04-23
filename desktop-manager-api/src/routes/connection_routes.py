from http import HTTPStatus
import logging
from typing import Any

from core.auth import token_required
from database.core.session import with_db_session
from flask import Blueprint, jsonify, request
from services.connections import APIError, ConnectionsService


connections_bp = Blueprint("connections_bp", __name__)


@connections_bp.route("/scaleup", methods=["POST"])
@with_db_session
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
        # Get input data
        data = request.get_json()
        current_user = request.current_user

        # Create service instance and call scale_up

        connection_service = ConnectionsService()
        response_data = connection_service.scale_up(data, current_user, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in scale_up: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logging.error("Unexpected error in scale_up: %s", str(e))
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@connections_bp.route("/scaledown", methods=["POST"])
@with_db_session
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
        # Get input data
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

        # Create service instance and call scale_down
        connection_service = ConnectionsService()
        response_data = connection_service.scale_down(connection_name, current_user, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in scale_down: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logging.error("Error in scale_down: %s", str(e))
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@connections_bp.route("/list", methods=["GET"])
@with_db_session
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

        # Create service instance and call list_connections
        connection_service = ConnectionsService()
        response_data = connection_service.list_connections(current_user, creator_filter, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in list_connections: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logging.error("Error listing connections: %s", str(e))
        return (
            jsonify({"error": "Internal server error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@connections_bp.route("/<connection_name>", methods=["GET"])
@with_db_session
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

    try:
        # Get authenticated user
        current_user = request.current_user

        # Create service instance and call get_connection
        connection_service = ConnectionsService()
        response_data = connection_service.get_connection(connection_name, current_user, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in get_connection: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logging.error("Error getting connection: %s", str(e))
        return jsonify({"error": "Internal server error", "details": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@connections_bp.route("/direct-connect/<string:connection_id>", methods=["GET"])
@with_db_session
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

        # Create service instance and call direct_connect
        connection_service = ConnectionsService()
        response_data = connection_service.direct_connect(connection_id, current_user, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in direct_connect: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
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

        # Create service instance and call guacamole_dashboard
        connection_service = ConnectionsService()
        response_data = connection_service.guacamole_dashboard(current_user)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in guacamole_dashboard: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logging.error("Error generating Guacamole dashboard auth URL: %s", str(e))
        return (
            jsonify({"error": "Internal server error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@connections_bp.route("/resume", methods=["POST"])
@with_db_session
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
    data = request.get_json()
    if not data or "name" not in data:
        return (
            jsonify({"error": "Missing required field: name"}),
            HTTPStatus.BAD_REQUEST,
        )

    connection_name = data["name"]
    current_user = request.current_user

    # Create service instance and call resume_connection
    connection_service = ConnectionsService()
    response_data = connection_service.resume_connection(connection_name, current_user, request.db_session)

    return jsonify(response_data), HTTPStatus.OK

    try:
        # Extract connection name from request
        data = request.get_json()
        if not data or "name" not in data:
            return (
                jsonify({"error": "Missing required field: name"}),
                HTTPStatus.BAD_REQUEST,
            )

        connection_name = data["name"]
        current_user = request.current_user

        # Create service instance and call resume_connection
        connection_service = ConnectionsService()
        response_data = connection_service.resume_connection(connection_name, current_user, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in resume_connection: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logging.error("Error in resume_connection: %s", str(e))
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@connections_bp.route("/permanent-delete", methods=["POST"])
@with_db_session
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

        # Create service instance and call permanent_delete
        connection_service = ConnectionsService()
        response_data = connection_service.permanent_delete(connection_name, current_user, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in permanent_delete: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logging.error("Error in permanent_delete: %s", str(e))
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@connections_bp.route("/attach-pvc", methods=["POST"])
@with_db_session
@token_required
def attach_pvc() -> tuple[dict[str, Any], int]:
    """Attach a PVC to a connection.

    This endpoint:
    1. Validates the request parameters
    2. Attaches the PVC to the connection
    3. Returns the updated connection details

    Returns:
        tuple: A tuple containing:
            - Dict with results
            - HTTP status code
    """
    try:
        # Get authenticated user

        # Extract connection name and PVC ID from request
        data = request.get_json()
        if not data or "connection_id" not in data or "pvc_id" not in data:
            return (
                jsonify({"error": "Missing required fields: connection_id and pvc_id"}),
                HTTPStatus.BAD_REQUEST,
            )

        connection_id = data["connection_id"]
        pvc_id = data["pvc_id"]

        # Create service instance and call attach_pvc
        connection_service = ConnectionsService()
        response_data = connection_service.attach_pvc_to_connection(
            connection_id, pvc_id, request.current_user, request.db_session
        )

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in attach_pvc: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logging.error("Error in attach_pvc: %s", str(e))
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@connections_bp.route("/detach-pvc", methods=["POST"])
@with_db_session
@token_required
def detach_pvc() -> tuple[dict[str, Any], int]:
    """Detach a PVC from a connection.

    This endpoint:
    1. Validates the request parameters
    2. Detaches the PVC from the connection
    3. Returns the updated connection details

    Returns:
        tuple: A tuple containing:
            - Dict with results
            - HTTP status code
    """
    try:
        # Get authenticated user
        current_user = request.current_user

        # Extract connection ID from request
        data = request.get_json()
        if not data or "connection_id" not in data:
            return (
                jsonify({"error": "Missing required field: connection_id"}),
                HTTPStatus.BAD_REQUEST,
            )

        connection_id = data["connection_id"]
        logging.info("Detaching PVC from connection: %s", connection_id)

        # Create service instance and call detach_pvc
        connection_service = ConnectionsService()
        response_data = connection_service.detach_pvc_from_connection(connection_id, current_user, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in detach_pvc: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logging.error("Error in detach_pvc: %s", str(e))
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR
