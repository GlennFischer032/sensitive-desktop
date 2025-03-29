from flask import abort, current_app, flash, jsonify, redirect, render_template, request, url_for

from app.clients.base import APIError
from app.clients.factory import client_factory
from app.configurations import configurations_bp
from app.middleware.auth import admin_required, login_required


@configurations_bp.route("/", methods=["GET"])
@login_required
@admin_required
def view_configurations():
    """
    Display all desktop configurations.
    This route is only accessible to admin users.
    """
    desktop_configs_client = client_factory.get_desktop_configurations_client()

    try:
        # Get all desktop configurations
        configurations = desktop_configs_client.list_configurations()
        return render_template("configurations.html", configurations=configurations)
    except Exception as e:
        current_app.logger.error(f"Error fetching configurations: {e}")
        flash(f"Error fetching configurations: {str(e)}", "error")
        return render_template("configurations.html", configurations=[])


@configurations_bp.route("/add", methods=["GET", "POST"])
@login_required
@admin_required
def add_configuration():
    """
    Add a new desktop configuration.
    This route is only accessible to admin users.
    """
    api_client = client_factory.get_desktop_configurations_client()

    if request.method == "POST":
        # Get form data
        data = {
            "name": request.form.get("name"),
            "description": request.form.get("description", ""),
            "image": request.form.get("image"),
            "min_cpu": int(request.form.get("min_cpu", 1)),
            "max_cpu": int(request.form.get("max_cpu", 4)),
            "min_ram": request.form.get("min_ram", "1024Mi"),
            "max_ram": request.form.get("max_ram", "4096Mi"),
            "is_public": "is_public" in request.form,
            "allowed_users": request.form.getlist("allowed_users")
            if "allowed_users" in request.form
            else [],
        }

        try:
            # Create the configuration
            api_client.create_configuration(data)
            flash("Configuration created successfully", "success")
            return redirect(url_for("configurations.view_configurations"))
        except Exception as e:
            current_app.logger.error(f"Error creating configuration: {e}")
            flash(f"Error creating configuration: {str(e)}", "error")

    # For GET requests or if POST fails, get all users for access control
    try:
        users_data = api_client.get_users()
        users = users_data.get("data", [])
    except Exception as e:
        current_app.logger.error(f"Error fetching users: {e}")
        users = []

    return render_template("add_configuration.html", users=users)


@configurations_bp.route("/<int:config_id>", methods=["GET"])
@login_required
def configuration_detail(config_id):
    """
    Display details of a specific desktop configuration.
    """
    api_client = client_factory.get_desktop_configurations_client()

    try:
        # Get the specific configuration
        configuration_data = api_client.get_configuration(config_id)
        configuration = configuration_data.get("data")

        if not configuration:
            flash("Configuration not found", "error")
            return redirect(url_for("configurations.view_configurations"))

        # Get allowed users if it's a private configuration
        allowed_users = []
        if not configuration.get("is_public"):
            users_data = api_client.get_configuration_users(config_id)
            allowed_users = users_data.get("data", [])

        # Get active connections using this configuration
        connections_data = api_client.get_connections()
        all_connections = connections_data.get("data", [])
        active_connections = [
            conn for conn in all_connections if conn.get("desktop_configuration_id") == config_id
        ]

        return render_template(
            "configuration_detail.html",
            configuration=configuration,
            allowed_users=allowed_users,
            active_connections=active_connections,
        )
    except Exception as e:
        current_app.logger.error(f"Error fetching configuration details: {e}")
        flash(f"Error fetching configuration details: {str(e)}", "error")
        return redirect(url_for("configurations.view_configurations"))


@configurations_bp.route("/<int:config_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def edit_configuration(config_id):
    """
    Edit an existing desktop configuration.
    This route is only accessible to admin users.
    """
    api_client = client_factory.get_desktop_configurations_client()

    if request.method == "POST":
        # Get form data
        data = {
            "name": request.form.get("name"),
            "description": request.form.get("description", ""),
            "image": request.form.get("image"),
            "min_cpu": int(request.form.get("min_cpu", 1)),
            "max_cpu": int(request.form.get("max_cpu", 4)),
            "min_ram": request.form.get("min_ram", "1024Mi"),
            "max_ram": request.form.get("max_ram", "4096Mi"),
            "is_public": "is_public" in request.form,
            "allowed_users": request.form.getlist("allowed_users")
            if "allowed_users" in request.form
            else [],
        }

        try:
            # Update the configuration
            api_client.update_configuration(config_id, data)
            flash("Configuration updated successfully", "success")
            return redirect(url_for("configurations.configuration_detail", config_id=config_id))
        except Exception as e:
            current_app.logger.error(f"Error updating configuration: {e}")
            flash(f"Error updating configuration: {str(e)}", "error")

    # For GET requests or if POST fails, get current configuration and users
    try:
        configuration_data = api_client.get_configuration(config_id)
        configuration = configuration_data.get("data")

        if not configuration:
            flash("Configuration not found", "error")
            return redirect(url_for("configurations.view_configurations"))

        # Get all users
        users_data = api_client.get_users()
        all_users = users_data.get("data", [])

        # Get allowed users for this configuration
        allowed_users_data = api_client.get_configuration_users(config_id)
        allowed_users = allowed_users_data.get("data", [])
        allowed_user_ids = [user.get("id") for user in allowed_users]

        return render_template(
            "edit_configuration.html",
            configuration=configuration,
            all_users=all_users,
            allowed_user_ids=allowed_user_ids,
        )
    except Exception as e:
        current_app.logger.error(f"Error fetching configuration data: {e}")
        flash(f"Error fetching configuration data: {str(e)}", "error")
        return redirect(url_for("configurations.view_configurations"))


@configurations_bp.route("/<int:config_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_configuration(config_id):
    """
    Delete a desktop configuration.
    This route is only accessible to admin users.
    """
    api_client = client_factory.get_desktop_configurations_client()

    try:
        api_client.delete_configuration(config_id)

        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            # For AJAX requests, return JSON
            return jsonify({"success": True, "message": "Configuration deleted successfully"})

        flash("Configuration deleted successfully", "success")
    except Exception as e:
        current_app.logger.error(f"Error deleting configuration: {e}")
        error_message = str(e)

        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            # For AJAX requests, return JSON error
            return jsonify({"success": False, "message": f"Error: {error_message}"}), 500

        flash(f"Error deleting configuration: {error_message}", "error")

    return redirect(url_for("configurations.view_configurations"))
