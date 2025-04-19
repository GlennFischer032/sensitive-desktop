import re

from clients.base import APIError
from clients.factory import client_factory
from flask import (
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from middleware.auth import token_required
from middleware.security import rate_limit

from . import connections_bp

# Constants
MAX_CONNECTION_NAME_LENGTH = 12


@connections_bp.route("/")
@token_required
def view_connections():
    """List all available connections for the current user.
    This endpoint displays a page with all connections accessible to the logged-in user.
    ---
    tags:
      - Connections
    responses:
      200:
        description: Connections displayed successfully
      500:
        description: Error fetching connections
    """
    try:
        current_app.logger.info("Fetching connections from API...")
        connections_client = client_factory.get_connections_client()
        connections = connections_client.list_connections(token=session["token"])

        # Fetch desktop configurations for the add connection modal
        try:
            desktop_configs_client = client_factory.get_desktop_configurations_client()
            desktop_configurations = desktop_configs_client.list_configurations(token=session["token"])
        except Exception as e:
            current_app.logger.error(f"Error fetching desktop configurations: {str(e)}")
            desktop_configurations = []

        storage_pvcs = []
        try:
            storage_client = client_factory.get_storage_client()
            storage_pvcs = storage_client.list_storage(token=session["token"])
        except Exception as e:
            current_app.logger.error(f"Error fetching storage PVCs: {str(e)}")

        # Enhance connections data with PVC information
        for conn in connections:
            # Check if the connection has an external PVC attached
            # The connection will have an 'external_pvc' field if a PVC is attached
            conn["has_external_pvc"] = bool(conn.get("external_pvc", False))

        current_app.logger.info(f"Found {len(connections)} connections")
        return render_template(
            "connections.html",
            connections=connections,
            desktop_configurations=desktop_configurations,
            storage_pvcs=storage_pvcs,
        )
    except APIError as e:
        current_app.logger.error(f"Error fetching connections: {e.message}")
        flash(f"Failed to fetch connections: {e.message}")
        return render_template("connections.html", connections=[])
    except Exception as e:
        current_app.logger.error(f"Error fetching connections: {str(e)}")
        flash(f"Error fetching connections: {str(e)}")
        return render_template("connections.html", connections=[])


@connections_bp.route("/add", methods=["POST"])
@token_required
@rate_limit(requests_per_minute=10)
def add_connection():  # noqa: PLR0911
    """Create a new connection.
    This endpoint allows users to create a new remote desktop connection.
    ---
    tags:
      - Connections
    parameters:
      - name: connection_name
        in: formData
        type: string
        required: true
        description: Name for the new connection
      - name: desktop_configuration_id
        in: formData
        type: integer
        required: false
        description: ID of the desktop configuration to use
      - name: persistent_home
        in: formData
        type: string
        required: false
        description: Whether to enable persistent home directory
      - name: external_pvc
        in: formData
        type: string
        required: false
        description: External PVC to mount
    responses:
      200:
        description: Connection created successfully
        schema:
          type: object
          properties:
            status:
              type: string
            message:
              type: string
      400:
        description: Invalid input parameters
      500:
        description: Error creating connection
    """
    try:
        connection_name = request.form.get("connection_name")
        if not connection_name:
            error_msg = "Connection name is required"
            return _return_connection_error(error_msg, 400)

        name_validation_result = _validate_connection_name(connection_name)
        if name_validation_result:
            return name_validation_result

        persistent_home_value = request.form.get("persistent_home", "off")
        persistent_home = persistent_home_value != "off"

        external_pvc = request.form.get("external_pvc")
        desktop_configuration_id = request.form.get("desktop_configuration_id")

        connection_data = _prepare_connection_data(
            connection_name, persistent_home, desktop_configuration_id, external_pvc
        )

        connections_client = client_factory.get_connections_client()
        try:
            connections_client.add_connection(**connection_data, token=session["token"])
        except APIError as e:
            current_app.logger.error(f"Failed to add connection: {e.message}")
            return _return_connection_error(e.message, e.status_code)
        except Exception as e:
            current_app.logger.error(f"Error adding connection: {str(e)}")
            return _return_connection_error(str(e), 500)

        success_msg = "Connection created successfully"
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"status": "success", "message": success_msg}), 200

        flash(success_msg, "success")
        return redirect(url_for("connections.view_connections"))

    except APIError as e:
        current_app.logger.error(f"Failed to add connection: {e.message}")
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"status": "error", "error": e.message}), 400
        flash(f"Failed to add connection: {e.message}")
    except Exception as e:
        current_app.logger.error(f"Error adding connection: {str(e)}")
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"status": "error", "error": str(e)}), 500
        flash(f"Error adding connection: {str(e)}")


def _validate_connection_name(connection_name):
    """Validate connection name and return error response if invalid."""
    name_pattern = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")
    if not name_pattern.match(connection_name):
        error_msg = (
            "Connection name must start and end with an alphanumeric character "
            "and contain only lowercase letters, numbers, and hyphens"
        )
        return _return_connection_error(error_msg, 400)

    if len(connection_name) > MAX_CONNECTION_NAME_LENGTH:
        error_msg = "Connection name is too long. Maximum length is 12 characters."
        return _return_connection_error(error_msg, 400)

    return None


def _return_connection_error(error_msg, status_code=400):
    """Return appropriate error response for connection operations."""
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"status": "error", "error": error_msg}), status_code
    flash(error_msg, "error")
    return redirect(url_for("connections"))


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


@connections_bp.route("/direct-connect/<connection_id>")
@token_required
def direct_connect(connection_id):
    """Connect to remote desktop via Guacamole.
    This endpoint redirects the user to Guacamole for direct connection to a remote desktop.
    ---
    tags:
      - Connections
    parameters:
      - name: connection_id
        in: path
        type: string
        required: true
        description: ID of the connection to connect to
    responses:
      302:
        description: Redirect to Guacamole connection
      500:
        description: Error connecting to desktop
    """
    try:
        connections_client = client_factory.get_connections_client()
        data = connections_client.direct_connect(connection_id, token=session["token"])

        guacamole_url = data.get("auth_url")

        if guacamole_url:
            current_app.logger.info(f"Redirecting to Guacamole URL: {guacamole_url}")
            return redirect(guacamole_url)
        else:
            flash("Invalid response from API: missing auth_url")
            return redirect(url_for("connections.view_connections"))

    except Exception as e:
        current_app.logger.error(f"Error connecting to desktop: {str(e)}")
        flash(f"Error connecting to desktop: {str(e)}")
        return redirect(url_for("connections.view_connections"))


@connections_bp.route("/guacamole-dashboard")
@token_required
def guacamole_dashboard():
    """Access the Guacamole dashboard with automatic authentication.
    This endpoint redirects to the Guacamole dashboard with automatic authentication.
    ---
    tags:
      - Connections
    responses:
      302:
        description: Redirect to Guacamole dashboard
      500:
        description: Error accessing Guacamole dashboard
    """
    try:
        connections_client = client_factory.get_connections_client()
        data = connections_client.guacamole_dashboard(token=session["token"])

        guacamole_url = data.get("auth_url")

        if guacamole_url:
            current_app.logger.info(f"Redirecting to Guacamole URL: {guacamole_url}")
            return redirect(guacamole_url)
        else:
            flash("Invalid response from API: missing auth_url")
            return redirect(url_for("connections.view_connections"))

    except Exception as e:
        current_app.logger.error(f"Error accessing Guacamole dashboard: {str(e)}")
        flash(f"Error accessing Guacamole dashboard: {str(e)}")
        return redirect(url_for("connections.view_connections"))
