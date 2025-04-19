"""API routes for connection management.

This module provides API endpoints for managing desktop connections, separate from UI routes.
"""

import re
from http import HTTPStatus

from clients.base import APIError
from clients.factory import client_factory
from flask import current_app, jsonify, request, session
from middleware.auth import token_required
from middleware.security import rate_limit

from . import connections_api_bp

# Constants
MAX_CONNECTION_NAME_LENGTH = 12


@connections_api_bp.route("/", methods=["GET"])
@token_required
def list_connections():
    """Get a list of all connections for the current user.
    ---
    tags:
      - Login Required Routes
    parameters:
      - name: username
        in: query
        type: string
        required: false
        description: Filter connections by username (admin only)
    responses:
      200:
        description: A list of connections
        schema:
          type: object
          properties:
            connections:
              type: array
              items:
                type: object
      500:
        description: Server error
    """
    try:
        username = None
        if request.args.get("username"):
            username = request.args.get("username")
            current_app.logger.info(f"API: Fetching connections for user: {username}")
        else:
            current_app.logger.info("API: Fetching connections for current user")

        connections_client = client_factory.get_connections_client()
        connections = connections_client.list_connections(username, token=session["token"])

        return jsonify({"connections": connections}), HTTPStatus.OK
    except APIError as e:
        current_app.logger.error(f"API Error fetching connections: {e.message}")
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        current_app.logger.error(f"API Error fetching connections: {str(e)}")
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@connections_api_bp.route("/", methods=["POST"])
@token_required
@rate_limit(requests_per_minute=10)
def create_connection():  # noqa: PLR0911
    """Create a new connection.
    ---
    tags:
      - Login Required Routes
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - name
          properties:
            name:
              type: string
              description: Name for the new connection
            persistent_home:
              type: boolean
              description: Whether to enable persistent home directory
            desktop_configuration_id:
              type: integer
              description: ID of desktop configuration to use
            external_pvc:
              type: string
              description: External PVC to mount
    responses:
      201:
        description: Connection created successfully
        schema:
          type: object
          properties:
            status:
              type: string
            message:
              type: string
      400:
        description: Invalid request data
      500:
        description: Server error
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), HTTPStatus.BAD_REQUEST

        connection_name = data.get("connection_name")
        if not connection_name:
            return jsonify({"error": "Connection name is required"}), HTTPStatus.BAD_REQUEST

        # Validate connection name
        validation_error = _validate_connection_name(connection_name)
        if validation_error:
            return validation_error

        # Extract parameters
        persistent_home = data.get("persistent_home", False)
        desktop_configuration_id = data.get("desktop_configuration_id")
        external_pvc = data.get("external_pvc")

        # Prepare connection data
        connection_data = _prepare_connection_data(
            connection_name, persistent_home, desktop_configuration_id, external_pvc
        )

        # Create connection
        current_app.logger.info(f"API: Creating new connection: {connection_name}")
        connections_client = client_factory.get_connections_client()
        try:
            connections_client.add_connection(**connection_data, token=session["token"])
        except APIError as e:
            current_app.logger.error(f"API Error creating connection: {e.message}")
            return jsonify({"status": "error", "error": e.message}), e.status_code
        except Exception as e:
            current_app.logger.error(f"API Error creating connection: {str(e)}")
            return jsonify({"status": "error", "error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR

        return jsonify({"status": "success", "message": "Connection created successfully"}), HTTPStatus.CREATED

    except APIError as e:
        current_app.logger.error(f"API Error creating connection: {e.message}")
        return jsonify({"status": "error", "error": e.message}), e.status_code
    except Exception as e:
        current_app.logger.error(f"API Error creating connection: {str(e)}")
        return jsonify({"status": "error", "error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@connections_api_bp.route("/<connection_name>/stop", methods=["POST"])
@token_required
@rate_limit(requests_per_minute=10)
def stop_connection(connection_name):
    """Stop a running connection.
    ---
    tags:
      - Login Required Routes
    parameters:
      - name: connection_name
        in: path
        type: string
        required: true
        description: Name of the connection to stop
    responses:
      200:
        description: Connection stopped successfully
        schema:
          type: object
          properties:
            status:
              type: string
            message:
              type: string
      404:
        description: Connection not foundVW
        description: Server error
    """
    try:
        current_app.logger.info(f"API: Stopping connection: {connection_name}")
        connections_client = client_factory.get_connections_client()
        connections_client.stop_connection(connection_name, token=session["token"])

        return jsonify({"status": "success", "message": "Connection stopped successfully"}), HTTPStatus.OK

    except APIError as e:
        current_app.logger.error(f"API Error stopping connection: {e.message}")
        return jsonify({"status": "error", "error": e.message}), e.status_code
    except Exception as e:
        current_app.logger.error(f"API Error stopping connection: {str(e)}")
        return jsonify({"status": "error", "error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@connections_api_bp.route("/<connection_name>/resume", methods=["POST"])
@token_required
@rate_limit(requests_per_minute=10)
def resume_connection(connection_name):
    """Resume a stopped connection.
    ---
    tags:
      - Login Required Routes
    parameters:
      - name: connection_name
        in: path
        type: string
        required: true
        description: Name of the connection to resume
    responses:
      200:
        description: Connection resumed successfully
        schema:
          type: object
          properties:
            status:
              type: string
            message:
              type: string
      404:
        description: Connection not found
      500:
        description: Server error
    """
    try:
        current_app.logger.info(f"API: Resuming connection: {connection_name}")
        connections_client = client_factory.get_connections_client()
        connections_client.resume_connection(connection_name, token=session["token"])

        return jsonify({"status": "success", "message": "Connection resumed successfully"}), HTTPStatus.OK

    except APIError as e:
        current_app.logger.error(f"API Error resuming connection: {e.message}")
        return jsonify({"status": "error", "error": e.message}), e.status_code
    except Exception as e:
        current_app.logger.error(f"API Error resuming connection: {str(e)}")
        return jsonify({"status": "error", "error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@connections_api_bp.route("/<connection_name>", methods=["DELETE"])
@token_required
@rate_limit(requests_per_minute=10)
def delete_connection(connection_name):
    """Delete a connection permanently.
    ---
    tags:
      - Login Required Routes
    parameters:
      - name: connection_name
        in: path
        type: string
        required: true
        description: Name of the connection to delete
    responses:
      200:
        description: Connection deleted successfully
        schema:
          type: object
          properties:
            status:
              type: string
            message:
              type: string
      404:
        description: Connection not found
      500:
        description: Server error
    """
    try:
        current_app.logger.info(f"API: Deleting connection: {connection_name}")
        connections_client = client_factory.get_connections_client()
        connections_client.delete_connection(connection_name, token=session["token"])

        return jsonify({"status": "success", "message": "Connection permanently deleted"}), HTTPStatus.OK

    except APIError as e:
        current_app.logger.error(f"API Error deleting connection: {e.message}")
        return jsonify({"status": "error", "error": e.message}), e.status_code
    except Exception as e:
        current_app.logger.error(f"API Error deleting connection: {str(e)}")
        return jsonify({"status": "error", "error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@connections_api_bp.route("/dashboard-auth-url", methods=["GET"])
@token_required
def get_dashboard_auth_url():
    """Get authentication URL for Guacamole dashboard.
    ---
    tags:
      - Login Required Routes
    responses:
      200:
        description: Dashboard authentication URL retrieved successfully
        schema:
          type: object
          properties:
            auth_url:
              type: string
      500:
        description: Server error
    """
    try:
        current_app.logger.info("API: Getting Guacamole dashboard auth URL")
        connections_client = client_factory.get_connections_client()
        data = connections_client.guacamole_dashboard(token=session["token"])

        return jsonify(data), HTTPStatus.OK

    except APIError as e:
        current_app.logger.error(f"API Error getting dashboard auth URL: {e.message}")
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        current_app.logger.error(f"API Error getting dashboard auth URL: {str(e)}")
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@connections_api_bp.route("/attach-pvc", methods=["POST"])
@token_required
def attach_pvc():
    """Attach a PVC to a connection.
    ---
    tags:
      - Login Required Routes
    parameters:
      - name: connection_id
        in: path
        type: string
        required: true
        description: ID of the connection to attach the PVC to
      - name: pvc_id
        in: body
        type: string
        required: true
        description: ID of the PVC to attach
    responses:
      200:
        description: PVC attached successfully
        schema:
          type: object
          properties:
            message:
              type: string
      400:
        description: Invalid request data
      500:
        description: Server error
    """
    try:
        current_app.logger.info("API: Attaching PVC to connection")
        data = request.get_json()
        connection_id = data.get("connection_id")
        pvc_id = data.get("pvc_id")

        connections_client = client_factory.get_connections_client()
        response_data = connections_client.attach_pvc_to_connection(connection_id, pvc_id, token=session["token"])

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        current_app.logger.error(f"API Error attaching PVC: {e.message}")
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        current_app.logger.error(f"API Error attaching PVC: {str(e)}")
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@connections_api_bp.route("/detach-pvc", methods=["POST"])
@token_required
def detach_pvc():
    """Detach a PVC from a connection.
    ---
    tags:
      - Login Required Routes
    parameters:
      - name: connection_id
        in: path
        type: string
        required: true
        description: ID of the connection to detach the PVC from
    responses:
      200:
        description: PVC detached successfully
        schema:
          type: object
          properties:
            message:
              type: string
      400:
        description: Invalid request data
      500:
        description: Server error
    """
    try:
        current_app.logger.info("API: Detaching PVC from connection")
        data = request.get_json()
        connection_id = data.get("connection_id")

        connections_client = client_factory.get_connections_client()
        response_data = connections_client.detach_pvc_from_connection(connection_id, token=session["token"])

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        current_app.logger.error(f"API Error detaching PVC: {e.message}")
        return jsonify({"error": e.message}), e.status_code


# Helper functions
def _validate_connection_name(connection_name):
    """Validate connection name and return error response if invalid."""
    name_pattern = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")
    if not name_pattern.match(connection_name):
        error_msg = (
            "Connection name must start and end with an alphanumeric character "
            "and contain only lowercase letters, numbers, and hyphens"
        )
        return jsonify({"status": "error", "error": error_msg}), HTTPStatus.BAD_REQUEST

    if len(connection_name) > MAX_CONNECTION_NAME_LENGTH:
        error_msg = f"Connection name is too long. Maximum length is {MAX_CONNECTION_NAME_LENGTH} characters."
        return jsonify({"status": "error", "error": error_msg}), HTTPStatus.BAD_REQUEST

    return None


def _prepare_connection_data(connection_name, persistent_home, desktop_configuration_id, external_pvc):
    """Prepare connection data for API call."""
    connection_data = {
        "name": connection_name,
        "persistent_home": persistent_home,
    }

    if desktop_configuration_id:
        connection_data["desktop_configuration_id"] = desktop_configuration_id

    # Add external PVC if specified
    if external_pvc:
        connection_data["external_pvc"] = external_pvc

    return connection_data
