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

from clients.base import APIError
from clients.factory import client_factory
from middleware.security import rate_limit
from utils.decorators import login_required

from . import connections_bp


@connections_bp.route("/")
@login_required
@rate_limit(requests_per_minute=30)  # Standard rate limit for viewing connections
def view_connections():
    try:
        current_app.logger.info("Fetching connections from API...")
        connections_client = client_factory.get_connections_client()
        connections = connections_client.list_connections()

        current_app.logger.info(f"Found {len(connections)} connections")
        return render_template("connections.html", connections=connections)
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
        connection_name = request.form.get("connection_name")

        if not connection_name:
            flash("Please provide a connection name")
            return render_template("add_connection.html")

        try:
            current_app.logger.info(f"Adding new connection: {connection_name}")
            connections_client = client_factory.get_connections_client()
            connections_client.add_connection(connection_name)

            flash("Connection added successfully")
            return redirect(url_for("connections.view_connections"))
        except APIError as e:
            current_app.logger.error(f"Failed to add connection: {e.message}")
            flash(f"Failed to add connection: {e.message}")
        except Exception as e:
            current_app.logger.error(f"Error adding connection: {str(e)}")
            flash(f"Error adding connection: {str(e)}")

    return render_template("add_connection.html")


@connections_bp.route("/delete/<connection_name>", methods=["POST"])
@login_required
@rate_limit(requests_per_minute=10)  # Stricter limit for deleting connections
def delete_connection(connection_name):
    try:
        current_app.logger.info(f"Deleting connection: {connection_name}")
        connections_client = client_factory.get_connections_client()
        connections_client.delete_connection(connection_name)

        flash("Connection deleted successfully")
    except APIError as e:
        current_app.logger.error(f"Failed to delete connection: {e.message}")
        flash(f"Failed to delete connection: {e.message}")
    except Exception as e:
        current_app.logger.error(f"Error deleting connection: {str(e)}")
        flash(f"Error deleting connection: {str(e)}")

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

        # Make the request to the API with auth token
        response = requests.get(api_url, headers={"Authorization": f"Bearer {token}"}, timeout=10)

        # Check for successful response
        if response.status_code == 200:
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
        if response.status_code == 200:
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
