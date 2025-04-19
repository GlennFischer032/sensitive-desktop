"""API routes for desktop configurations management.

This module provides API endpoints for managing desktop configurations, separate from UI routes.
"""

from http import HTTPStatus

from clients.base import APIError
from clients.factory import client_factory
from flask import current_app, jsonify, request, session
from middleware.auth import admin_required, token_required

from . import configurations_api_bp


@configurations_api_bp.route("/", methods=["GET"])
@token_required
def list_configurations():
    """Get a list of all desktop configurations.
    ---
    tags:
      - Login Required Routes
    responses:
      200:
        description: A list of desktop configurations
        schema:
          type: object
          properties:
            configurations:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: integer
                  name:
                    type: string
                  description:
                    type: string
                  is_public:
                    type: boolean
      500:
        description: Server error
    """
    try:
        current_app.logger.info("API: Fetching desktop configurations")
        desktop_configs_client = client_factory.get_desktop_configurations_client()
        configs = desktop_configs_client.list_configurations(token=session["token"])

        return jsonify({"configurations": configs}), HTTPStatus.OK
    except APIError as e:
        current_app.logger.error(f"API Error fetching configurations: {e.message}")
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        current_app.logger.error(f"API Error fetching configurations: {str(e)}")
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@configurations_api_bp.route("/<int:config_id>", methods=["GET"])
@token_required
def get_configuration(config_id):
    """Get details for a specific desktop configuration.
    ---
    tags:
      - Login Required Routes
    parameters:
      - name: config_id
        in: path
        type: integer
        required: true
        description: ID of the configuration to retrieve
    responses:
      200:
        description: Configuration details
        schema:
          type: object
          properties:
            configuration:
              type: object
      404:
        description: Configuration not found
      500:
        description: Server error
    """
    try:
        current_app.logger.info(f"API: Fetching configuration with ID: {config_id}")
        desktop_configs_client = client_factory.get_desktop_configurations_client()
        config_response = desktop_configs_client.get_configuration(config_id=config_id, token=session["token"])

        return jsonify(config_response), HTTPStatus.OK
    except APIError as e:
        current_app.logger.error(f"API Error fetching configuration: {e.message}")
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        current_app.logger.error(f"API Error fetching configuration: {str(e)}")
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@configurations_api_bp.route("/", methods=["POST"])
@token_required
@admin_required
def create_configuration():
    """Create a new desktop configuration.
    ---
    tags:
      - Admin Required Routes
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
              description: Name for the configuration
            description:
              type: string
              description: Description of the configuration
            is_public:
              type: boolean
              description: Whether the configuration is publicly accessible
            min_cpu:
              type: number
              description: Minimum CPU cores
            max_cpu:
              type: number
              description: Maximum CPU cores
            min_ram:
              type: number
              description: Minimum RAM in GB
            max_ram:
              type: number
              description: Maximum RAM in GB
            user_ids:
              type: array
              items:
                type: integer
              description: List of user IDs allowed to use this configuration
    responses:
      201:
        description: Configuration created successfully
        schema:
          type: object
          properties:
            success:
              type: boolean
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

        current_app.logger.info(f"API: Creating new configuration: {data.get('name')}")
        desktop_configs_client = client_factory.get_desktop_configurations_client()
        desktop_configs_client.create_configuration(config_data=data, token=session["token"])

        return jsonify({"success": True, "message": "Configuration created successfully"}), HTTPStatus.CREATED
    except APIError as e:
        current_app.logger.error(f"API Error creating configuration: {e.message}")
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        current_app.logger.error(f"API Error creating configuration: {str(e)}")
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@configurations_api_bp.route("/<int:config_id>", methods=["PUT"])
@token_required
@admin_required
def update_configuration(config_id):
    """Update an existing desktop configuration.
    ---
    tags:
      - Admin Required Routes
    parameters:
      - name: config_id
        in: path
        type: integer
        required: true
        description: ID of the configuration to update
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            name:
              type: string
              description: Name for the configuration
            description:
              type: string
              description: Description of the configuration
            is_public:
              type: boolean
              description: Whether the configuration is publicly accessible
            min_cpu:
              type: number
              description: Minimum CPU cores
            max_cpu:
              type: number
              description: Maximum CPU cores
            min_ram:
              type: number
              description: Minimum RAM in GB
            max_ram:
              type: number
              description: Maximum RAM in GB
            user_ids:
              type: array
              items:
                type: integer
              description: List of user IDs allowed to use this configuration
    responses:
      200:
        description: Configuration updated successfully
        schema:
          type: object
          properties:
            success:
              type: boolean
            message:
              type: string
      400:
        description: Invalid request data
      404:
        description: Configuration not found
      500:
        description: Server error
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), HTTPStatus.BAD_REQUEST

        current_app.logger.info(f"API: Updating configuration with ID: {config_id}")
        desktop_configs_client = client_factory.get_desktop_configurations_client()
        desktop_configs_client.update_configuration(config_id=config_id, config_data=data, token=session["token"])

        return jsonify({"success": True, "message": "Configuration updated successfully"}), HTTPStatus.OK
    except APIError as e:
        current_app.logger.error(f"API Error updating configuration: {e.message}")
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        current_app.logger.error(f"API Error updating configuration: {str(e)}")
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@configurations_api_bp.route("/<int:config_id>", methods=["DELETE"])
@token_required
@admin_required
def delete_configuration(config_id):
    """Delete a desktop configuration.
    ---
    tags:
      - Admin Required Routes
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
      404:
        description: Configuration not found
      500:
        description: Server error
    """
    try:
        current_app.logger.info(f"API: Deleting configuration with ID: {config_id}")
        desktop_configs_client = client_factory.get_desktop_configurations_client()
        desktop_configs_client.delete_configuration(config_id=config_id, token=session["token"])

        return jsonify({"success": True, "message": "Configuration deleted successfully"}), HTTPStatus.OK
    except APIError as e:
        current_app.logger.error(f"API Error deleting configuration: {e.message}")
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        current_app.logger.error(f"API Error deleting configuration: {str(e)}")
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR
