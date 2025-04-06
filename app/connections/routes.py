import re
from http import HTTPStatus

import requests
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

from app.clients.base import APIError
from app.clients.factory import client_factory
from app.middleware.security import rate_limit
from app.utils.decorators import login_required

from . import connections_bp

# Constants
MAX_CONNECTION_NAME_LENGTH = 12


@connections_bp.route("/")
@login_required
@rate_limit(requests_per_minute=30)  # Standard rate limit for viewing connections
def view_connections():
    try:
        current_app.logger.info("Fetching connections from API...")
        connections_client = client_factory.get_connections_client()
        connections = connections_client.list_connections()

        # Fetch desktop configurations for the add connection modal
        try:
            desktop_configs_client = client_factory.get_desktop_configurations_client()
            desktop_configurations = desktop_configs_client.list_configurations()
        except Exception as e:
            current_app.logger.error(f"Error fetching desktop configurations: {str(e)}")
            desktop_configurations = []

        # Fetch storage PVCs for admin users
        storage_pvcs = []
        is_admin = session.get("is_admin", False)
        if is_admin:
            try:
                storage_client = client_factory.get_storage_client()
                storage_pvcs = storage_client.list_pvcs()
            except Exception as e:
                current_app.logger.error(f"Error fetching storage PVCs: {str(e)}")

        current_app.logger.info(f"Found {len(connections)} connections")
        return render_template(
            "connections.html",
            connections=connections,
            desktop_configurations=desktop_configurations,
            is_admin=is_admin,
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


@connections_bp.route("/add", methods=["GET", "POST"])
@login_required
@rate_limit(requests_per_minute=10)  # Stricter limit for adding connections
def add_connection():
    if request.method == "POST":
        try:
            return _handle_add_connection_post()
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

    # For GET requests or if POST fails, fetch desktop configurations for the form
    return _handle_add_connection_get()


def _handle_add_connection_post():
    """Handle POST request for add_connection route."""
    connection_name = request.form.get("connection_name")
    if not connection_name:
        error_msg = "Connection name is required"
        return _return_connection_error(error_msg, 400)

    # Validate name against required pattern and length
    name_validation_result = _validate_connection_name(connection_name)
    if name_validation_result:
        return name_validation_result

    # Get desktop configuration if specified
    desktop_configuration = _get_desktop_configuration()

    # Get persistent home setting
    persistent_home_value = request.form.get("persistent_home", "off")
    persistent_home = persistent_home_value != "off"

    # Get external PVC if specified (admin only)
    external_pvc = _get_external_pvc()

    # Create connection
    connection_data = _prepare_connection_data(connection_name, persistent_home, desktop_configuration, external_pvc)

    connections_client = client_factory.get_connections_client()
    connections_client.add_connection(**connection_data)

    success_msg = "Connection created successfully"
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"status": "success", "message": success_msg}), 200

    flash(success_msg, "success")
    return redirect(url_for("connections.view_connections"))


def _validate_connection_name(connection_name):
    """Validate connection name and return error response if invalid."""
    # Validate name against required pattern and length
    name_pattern = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")
    if not name_pattern.match(connection_name):
        error_msg = (
            "Connection name must start and end with an alphanumeric character "
            "and contain only lowercase letters, numbers, and hyphens"
        )
        return _return_connection_error(error_msg, 400)

    # Check for the 12 character limit
    if len(connection_name) > MAX_CONNECTION_NAME_LENGTH:
        error_msg = "Connection name is too long. Maximum length is 12 characters."
        return _return_connection_error(error_msg, 400)

    return None


def _return_connection_error(error_msg, status_code=400):
    """Return appropriate error response for connection operations."""
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"status": "error", "error": error_msg}), status_code
    flash(error_msg, "error")
    return redirect(url_for("connections.add_connection"))


def _get_desktop_configuration():
    """Get desktop configuration if specified in the request."""
    desktop_configuration_id = request.form.get("desktop_configuration_id")
    desktop_configuration = None
    if desktop_configuration_id:
        desktop_configs_client = client_factory.get_desktop_configurations_client()
        config_response = desktop_configs_client.get_configuration(int(desktop_configuration_id))
        # Extract the configuration from the response
        desktop_configuration = config_response.get("configuration", {})
        current_app.logger.debug(f"Retrieved desktop configuration: {desktop_configuration}")
    return desktop_configuration


def _get_external_pvc():
    """Get external PVC if specified and user is admin."""
    external_pvc = request.form.get("external_pvc")
    if external_pvc and not session.get("is_admin", False):
        current_app.logger.warning("Non-admin user attempted to use external PVC")
        external_pvc = None  # Clear it for non-admins

    if external_pvc:
        current_app.logger.info(f"Using external PVC: {external_pvc}")

    return external_pvc


def _prepare_connection_data(connection_name, persistent_home, desktop_configuration, external_pvc):
    """Prepare connection data for API call."""
    connection_data = {
        "name": connection_name,
        "persistent_home": persistent_home,
    }

    if desktop_configuration:
        connection_data.update(
            {
                "desktop_configuration_id": desktop_configuration.get("id"),
                "min_cpu": desktop_configuration.get("min_cpu"),
                "max_cpu": desktop_configuration.get("max_cpu"),
                "min_ram": desktop_configuration.get("min_ram"),
                "max_ram": desktop_configuration.get("max_ram"),
            }
        )

    # Add external PVC if specified
    if external_pvc:
        connection_data["external_pvc"] = external_pvc

    return connection_data


def _handle_add_connection_get():
    """Handle GET request for add_connection route."""
    try:
        desktop_configs_client = client_factory.get_desktop_configurations_client()
        desktop_configurations = desktop_configs_client.list_configurations()
    except Exception as e:
        current_app.logger.error(f"Error fetching desktop configurations: {str(e)}")
        desktop_configurations = []

    # Fetch storage PVCs for admin users
    storage_pvcs = []
    is_admin = session.get("is_admin", False)
    if is_admin:
        try:
            storage_client = client_factory.get_storage_client()
            storage_pvcs = storage_client.list_pvcs()
        except Exception as e:
            current_app.logger.error(f"Error fetching storage PVCs: {str(e)}")

    return render_template(
        "add_connection.html",
        desktop_configurations=desktop_configurations,
        is_admin=is_admin,
        storage_pvcs=storage_pvcs,
    )


@connections_bp.route("/delete/<connection_name>", methods=["POST"])
@login_required
@rate_limit(requests_per_minute=10)  # Stricter limit for deleting connections
def delete_connection(connection_name):
    try:
        current_app.logger.info(f"Deleting connection: {connection_name}")
        connections_client = client_factory.get_connections_client()
        connections_client.delete_connection(connection_name)

        flash("Connection stopped successfully")
    except APIError as e:
        current_app.logger.error(f"Failed to delete connection: {e.message}")
        flash(f"Failed to stop connection: {e.message}")
    except Exception as e:
        current_app.logger.error(f"Error deleting connection: {str(e)}")
        flash(f"Error stopping connection: {str(e)}")

    # If it's an AJAX request, return JSON response
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"status": "success"}), 200

    return redirect(url_for("connections.view_connections"))


@connections_bp.route("/direct-connect/<connection_id>")
@login_required
@rate_limit(requests_per_minute=10)  # Rate limit direct connections
def direct_connect(connection_id):
    """Handle connection to remote desktop via Guacamole.

    This endpoint makes a request to the API to get the Guacamole auth URL,
    then redirects the user to that URL for a seamless connection experience.
    """
    try:
        token = session.get("token")
        if not token:
            flash("Authentication required")
            return redirect(url_for("auth.login"))

        # Construct the API URL for direct connection
        api_url = f"{current_app.config['API_URL']}/api/connections/direct-connect/{connection_id}"

        # Log the request for debugging
        current_app.logger.info(f"Making API request to {api_url}")

        # Make the request to the API with auth token
        response = requests.get(api_url, headers={"Authorization": f"Bearer {token}"}, timeout=10)

        # Check for successful response
        if response.status_code == HTTPStatus.OK:
            # Get the Guacamole auth URL from the response
            data = response.json()
            guacamole_url = data.get("auth_url")

            # Log the received data
            current_app.logger.info(f"Received connection data: {data}")

            if guacamole_url:
                # Just use the auth URL directly without modification
                # The backend should already have properly configured it for direct connection
                current_app.logger.info(f"Redirecting to Guacamole URL: {guacamole_url}")
                return redirect(guacamole_url)
            else:
                flash("Invalid response from API: missing auth_url")
                return redirect(url_for("connections.view_connections"))
        else:
            flash(f"API Error: {response.status_code} - {response.text}")
            return redirect(url_for("connections.view_connections"))

    except Exception as e:
        current_app.logger.error(f"Error connecting to desktop: {str(e)}")
        flash(f"Error connecting to desktop: {str(e)}")
        return redirect(url_for("connections.view_connections"))


@connections_bp.route("/guacamole-dashboard")
@login_required
@rate_limit(requests_per_minute=10)  # Rate limit dashboard access
def guacamole_dashboard():
    """Access the Guacamole dashboard with automatic authentication.

    This endpoint makes a request to the API to get the Guacamole dashboard auth URL,
    then redirects the user to that URL for a seamless experience.
    """
    try:
        token = session.get("token")
        if not token:
            flash("Authentication required")
            return redirect(url_for("auth.login"))

        # Construct the API URL for Guacamole dashboard
        api_url = f"{current_app.config['API_URL']}/api/connections/guacamole-dashboard"

        # Make the request to the API with auth token
        response = requests.get(api_url, headers={"Authorization": f"Bearer {token}"}, timeout=10)

        # Check for successful response
        if response.status_code == HTTPStatus.OK:
            # Get the Guacamole auth URL from the response
            data = response.json()
            guacamole_url = data.get("auth_url")

            if guacamole_url:
                # Redirect to the Guacamole auth URL
                return redirect(guacamole_url)
            else:
                flash("Invalid response from API: missing auth_url")
                return redirect(url_for("connections.view_connections"))
        else:
            flash(f"API Error: {response.status_code} - {response.text}")
            return redirect(url_for("connections.view_connections"))

    except Exception as e:
        current_app.logger.error(f"Error accessing Guacamole dashboard: {str(e)}")
        flash(f"Error accessing Guacamole dashboard: {str(e)}")
        return redirect(url_for("connections.view_connections"))


@connections_bp.route("/resume/<connection_name>", methods=["POST"])
@login_required
@rate_limit(requests_per_minute=10)  # Stricter limit for resuming connections
def resume_connection(connection_name):
    try:
        current_app.logger.info(f"Resuming connection: {connection_name}")

        # Extract connection name from JSON body if present
        if request.is_json:
            data = request.get_json()
            if data and "name" in data:
                connection_name = data["name"]
                current_app.logger.info(f"Using connection name from JSON body: {connection_name}")

        connections_client = client_factory.get_connections_client()
        connections_client.resume_connection(connection_name)

        # If it's an AJAX request, return JSON response
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"status": "success", "message": "Connection resumed successfully"}), 200

        flash("Connection resumed successfully")
        return redirect(url_for("connections.view_connections"))

    except APIError as e:
        current_app.logger.error(f"Failed to resume connection: {e.message}")

        # If it's an AJAX request, return JSON error response
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"status": "error", "message": f"Failed to resume connection: {e.message}"}), 400

        flash(f"Failed to resume connection: {e.message}")
        return redirect(url_for("connections.view_connections"))

    except Exception as e:
        current_app.logger.error(f"Error resuming connection: {str(e)}")

        # If it's an AJAX request, return JSON error response
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"status": "error", "message": f"Error resuming connection: {str(e)}"}), 500

        flash(f"Error resuming connection: {str(e)}")
        return redirect(url_for("connections.view_connections"))


@connections_bp.route("/permanent-delete/<connection_name>", methods=["POST"])
@login_required
@rate_limit(requests_per_minute=10)  # Stricter limit for permanent deletion
def permanent_delete_connection(connection_name):
    try:
        current_app.logger.info(f"Permanently deleting connection: {connection_name}")

        # Extract connection name from JSON body if present
        if request.is_json:
            data = request.get_json()
            if data and "name" in data:
                connection_name = data["name"]
                current_app.logger.info(f"Using connection name from JSON body: {connection_name}")

        connections_client = client_factory.get_connections_client()
        connections_client.permanent_delete_connection(connection_name)

        # If it's an AJAX request, return JSON response
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"status": "success", "message": "Connection permanently deleted"}), 200

        flash("Connection permanently deleted")
        return redirect(url_for("connections.view_connections"))

    except APIError as e:
        current_app.logger.error(f"Failed to permanently delete connection: {e.message}")

        # If it's an AJAX request, return JSON error response
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify(
                {
                    "status": "error",
                    "message": f"Failed to permanently delete connection: {e.message}",
                }
            ), 400

        flash(f"Failed to permanently delete connection: {e.message}")
        return redirect(url_for("connections.view_connections"))

    except Exception as e:
        current_app.logger.error(f"Error permanently deleting connection: {str(e)}")

        # If it's an AJAX request, return JSON error response
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"status": "error", "message": f"Error permanently deleting connection: {str(e)}"}), 500

        flash(f"Error permanently deleting connection: {str(e)}")
        return redirect(url_for("connections.view_connections"))
