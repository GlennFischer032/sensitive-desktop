"""Routes for desktop configurations."""
import logging
from typing import Dict, Optional

from flask import flash, jsonify, redirect, render_template, request, url_for
from werkzeug.wrappers import Response

from app.clients.base import APIError
from app.clients.factory import client_factory
from app.middleware.auth import admin_required, login_required

from . import configurations_bp

logger = logging.getLogger(__name__)


@configurations_bp.route("/")
@login_required
def list_configurations() -> str:
    """List all desktop configurations.
    This endpoint displays a page with all available desktop configurations.
    ---
    tags:
      - Configurations
    responses:
      200:
        description: List of configurations displayed successfully
      500:
        description: Error fetching configurations
    """
    try:
        desktop_configs_client = client_factory.get_desktop_configurations_client()
        configs = desktop_configs_client.list_configurations()

        # Get all users for the modal form
        try:
            users_data = desktop_configs_client.get_users()
            all_users = users_data.get("data", [])
        except APIError as e:
            logger.error(f"Error fetching users: {str(e)}")
            all_users = []

        return render_template("configurations.html", configurations=configs, users=all_users)
    except APIError as e:
        logger.error(f"Error listing configurations: {str(e)}")
        flash(f"Error listing configurations: {str(e)}", "error")
        return render_template("configurations.html", configurations=[])


@configurations_bp.route("/create", methods=["GET", "POST"])
@admin_required
def create_configuration() -> Response | str:
    """Create a new desktop configuration.
    This endpoint allows administrators to create a new desktop configuration.
    ---
    tags:
      - Configurations
    methods:
      - GET
      - POST
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            name:
              type: string
              description: Configuration name
            description:
              type: string
              description: Configuration description
            is_public:
              type: boolean
              description: Whether configuration is public
            user_ids:
              type: array
              items:
                type: integer
              description: IDs of users with access to this configuration
    responses:
      200:
        description: Configuration form displayed (GET)
      201:
        description: Configuration created successfully (POST)
        schema:
          type: object
          properties:
            success:
              type: boolean
            message:
              type: string
      400:
        description: Error creating configuration
    """
    if request.method == "POST":
        try:
            config_data = request.get_json()

            desktop_configs_client = client_factory.get_desktop_configurations_client()
            desktop_configs_client.create_configuration(
                config_data=config_data,
            )

            return jsonify({"success": True, "message": "Configuration created successfully"}), 201

        except (APIError, ValueError) as e:
            logger.error(f"Error creating configuration: {str(e)}")
            return jsonify({"error": str(e)}), 400

    # Get all non-admin users for the form
    try:
        users_data = desktop_configs_client.get_users()
        all_users = users_data.get("data", [])
        default_config = {"is_public": True}
    except APIError as e:
        logger.error(f"Error fetching users: {str(e)}")
        all_users = []
        default_config = {"is_public": True}

    return render_template("configuration_form.html", configuration=default_config, users=all_users)


@configurations_bp.route("/edit/<int:config_id>", methods=["GET", "POST"])
@admin_required
def edit_configuration(config_id: int) -> Response | str:
    """Edit an existing desktop configuration.
    This endpoint allows administrators to edit an existing desktop configuration.
    ---
    tags:
      - Configurations
    methods:
      - GET
      - POST
    parameters:
      - name: config_id
        in: path
        type: integer
        required: true
        description: ID of the configuration to edit
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            name:
              type: string
              description: Configuration name
            description:
              type: string
              description: Configuration description
            is_public:
              type: boolean
              description: Whether configuration is public
            user_ids:
              type: array
              items:
                type: integer
              description: IDs of users with access to this configuration
    responses:
      200:
        description: Configuration data returned (GET) or updated successfully (POST)
      400:
        description: Error updating configuration
      404:
        description: Configuration not found
    """
    try:
        config: Optional[Dict] = None

        desktop_configs_client = client_factory.get_desktop_configurations_client()

        if request.method == "GET":
            config_response = desktop_configs_client.get_configuration(config_id)
            return jsonify(config_response), 200

        if request.method == "POST":
            config_data = request.get_json()

            desktop_configs_client.update_configuration(
                config_id=config_id,
                config_data=config_data,
            )

            return jsonify({"success": True, "message": "Configuration updated successfully"}), 200

        # Get all users for the form
        try:
            users_data = desktop_configs_client.get_users()
            all_users = users_data.get("data", [])
        except APIError as e:
            logger.error(f"Error fetching users: {str(e)}")
            all_users = []

        return render_template("configurationa.html", configuration=config, users=all_users)
    except APIError as e:
        logger.error(f"Error with configuration {config_id}: {str(e)}")
        flash(f"Error with configuration: {str(e)}", "error")
        return redirect(url_for("configurations.list_configurations"))


@configurations_bp.route("/delete/<int:config_id>", methods=["POST"])
@admin_required
def delete_configuration(config_id: int) -> Response:
    """Delete a desktop configuration.
    This endpoint allows administrators to delete an existing desktop configuration.
    ---
    tags:
      - Configurations
    methods:
      - POST
    parameters:
      - name: config_id
        in: path
        type: integer
        required: true
        description: ID of the configuration to delete
    responses:
      200:
        description: Configuration deleted successfully
        schema:
          type: object
          properties:
            success:
              type: boolean
            message:
              type: string
      400:
        description: Error deleting configuration
      404:
        description: Configuration not found
    """
    try:
        desktop_configs_client = client_factory.get_desktop_configurations_client()
        desktop_configs_client.delete_configuration(
            config_id=config_id,
        )

        # Handle AJAX requests
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            response = jsonify({"success": True, "message": "Configuration deleted successfully"})
            response.headers.add("Content-Type", "application/json")
            return response, 200

        flash("Configuration deleted successfully", "success")
    except Exception as e:
        logger.error(f"Error deleting configuration {config_id}: {str(e)}")

        # Handle AJAX requests
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            response = jsonify({"error": str(e)})
            response.headers.add("Content-Type", "application/json")
            return response, 400

        flash(f"Error deleting configuration: {str(e)}", "error")

    return redirect(url_for("configurations.list_configurations"))
