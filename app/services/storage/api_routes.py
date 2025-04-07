"""API routes for storage management.

This module provides API endpoints for managing storage PVCs, separate from UI routes.
"""

from http import HTTPStatus

from flask import current_app, jsonify, request

from app.clients.base import APIError
from app.clients.factory import client_factory
from app.middleware.auth import admin_required, login_required

from . import storage_api_bp


@storage_api_bp.route("/pvcs", methods=["GET"])
@login_required
def list_pvcs():
    """Get a list of all storage PVCs.
    ---
    tags:
      - Storage API
    responses:
      200:
        description: A list of storage PVCs
        schema:
          type: object
          properties:
            pvcs:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: integer
                  name:
                    type: string
                  size:
                    type: string
                  status:
                    type: string
                  created_at:
                    type: string
                    format: date-time
                  is_public:
                    type: boolean
      500:
        description: Server error
    """
    try:
        current_app.logger.info("API: Fetching storage PVCs")
        storage_client = client_factory.get_storage_client()
        pvcs = storage_client.list_storage()

        return jsonify({"pvcs": pvcs}), HTTPStatus.OK
    except Exception as e:
        current_app.logger.error(f"API Error fetching storage PVCs: {str(e)}")
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@storage_api_bp.route("/pvcs/<int:pvc_id>", methods=["GET"])
@login_required
def get_pvc(pvc_id):
    """Get details for a specific PVC.
    ---
    tags:
      - Storage API
    parameters:
      - name: pvc_id
        in: path
        type: integer
        required: true
        description: ID of the PVC to retrieve
    responses:
      200:
        description: PVC details
        schema:
          type: object
      401:
        description: Authentication required
      404:
        description: PVC not found
      500:
        description: Server error
    """
    try:
        storage_client = client_factory.get_storage_client()
        pvc = storage_client.get_storage(pvc_id)

        return jsonify(pvc)
    except Exception as e:
        current_app.logger.error(f"Error fetching PVC: {str(e)}")
        return jsonify({"error": str(e)}), 500


@storage_api_bp.route("/pvcs", methods=["POST"])
@login_required
@admin_required
def create_pvc():
    """Create a new storage PVC.
    ---
    tags:
      - Storage API
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - name
            - size
          properties:
            name:
              type: string
              description: Name for the new PVC
            size:
              type: string
              description: Size of the PVC (e.g., "10Gi")
            storage_class:
              type: string
              description: Kubernetes storage class to use
            is_public:
              type: boolean
              description: Whether the PVC is publicly accessible
            allowed_users:
              type: array
              items:
                type: integer
              description: List of user IDs allowed to access this PVC
    responses:
      201:
        description: PVC created successfully
        schema:
          type: object
      400:
        description: Invalid request data
      500:
        description: Server error
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), HTTPStatus.BAD_REQUEST

        # Validate required fields
        if "name" not in data or "size" not in data:
            return jsonify({"error": "Name and size are required"}), HTTPStatus.BAD_REQUEST

        current_app.logger.info(f"API: Creating new PVC with name: {data['name']}")
        storage_client = client_factory.get_storage_client()
        pvc = storage_client.create_storage(**data)

        return jsonify(pvc), HTTPStatus.CREATED
    except Exception as e:
        current_app.logger.error(f"API Error creating PVC: {str(e)}")
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@storage_api_bp.route("/pvcs/access/<int:pvc_id>", methods=["GET"])
@login_required
def get_pvc_access(pvc_id):
    """Get access control information for a PVC.
    ---
    tags:
      - Storage API
    parameters:
      - name: pvc_id
        in: path
        type: integer
        required: true
        description: ID of the PVC to get access information for
    responses:
      200:
        description: PVC access information
        schema:
          type: object
          properties:
            is_public:
              type: boolean
            allowed_users:
              type: array
              items:
                type: integer
      404:
        description: PVC not found
      500:
        description: Server error
    """
    try:
        storage_client = client_factory.get_storage_client()
        data = storage_client.get_pvc_access(pvc_id)
        return jsonify(data), HTTPStatus.OK
    except APIError as e:
        current_app.logger.error(f"API Error getting PVC access: {str(e)}")
        return jsonify({"error": str(e)}), e.status_code
    except Exception as e:
        current_app.logger.error(f"API Error getting PVC access: {str(e)}")
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@storage_api_bp.route("/pvcs/access/<int:pvc_id>", methods=["POST"])
@login_required
@admin_required
def update_pvc_access(pvc_id):
    """Update access control for a PVC.
    ---
    tags:
      - Storage API
    parameters:
      - name: pvc_id
        in: path
        type: integer
        required: true
        description: ID of the PVC to update
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            is_public:
              type: boolean
              description: Whether the PVC is publicly accessible
            allowed_users:
              type: array
              items:
                type: integer
              description: List of user IDs allowed to access this PVC
    responses:
      200:
        description: PVC access updated successfully
        schema:
          type: object
      400:
        description: Invalid request data
      404:
        description: PVC not found
      500:
        description: Server error
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), HTTPStatus.BAD_REQUEST

        is_public = data.get("is_public", False)
        allowed_users = data.get("allowed_users", [])

        storage_client = client_factory.get_storage_client()
        result = storage_client.update_pvc_access(pvc_id, is_public, allowed_users)
        return jsonify(result), HTTPStatus.OK
    except APIError as e:
        current_app.logger.error(f"API Error updating PVC access: {str(e)}")
        return jsonify({"error": str(e)}), e.status_code
    except Exception as e:
        current_app.logger.error(f"API Error updating PVC access: {str(e)}")
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@storage_api_bp.route("/pvcs/connections/<int:pvc_id>", methods=["GET"])
@login_required
def get_pvc_connections(pvc_id):
    """Get connections using a specific PVC.
    ---
    tags:
      - Storage API
    parameters:
      - name: pvc_id
        in: path
        type: integer
        required: true
        description: ID of the PVC to get connections for
    responses:
      200:
        description: List of connections using this PVC
        schema:
          type: object
          properties:
            connections:
              type: array
              items:
                type: object
      404:
        description: PVC not found
      500:
        description: Server error
    """
    try:
        storage_client = client_factory.get_storage_client()
        connections = storage_client.get_pvc_connections(pvc_id)
        return jsonify(connections), HTTPStatus.OK
    except Exception as e:
        current_app.logger.error(f"API Error fetching PVC connections: {str(e)}")
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@storage_api_bp.route("/pvcs/<string:pvc_name>", methods=["DELETE"])
@login_required
@admin_required
def delete_pvc(pvc_name):
    """Delete a PVC by name.
    ---
    tags:
      - Storage API
    parameters:
      - name: pvc_name
        in: path
        type: string
        required: true
        description: Name of the PVC to delete
    responses:
      200:
        description: PVC deleted successfully
        schema:
          type: object
          properties:
            message:
              type: string
      404:
        description: PVC not found
      500:
        description: Server error
    """
    try:
        current_app.logger.info(f"API: Deleting PVC: {pvc_name}")
        storage_client = client_factory.get_storage_client()
        result = storage_client.delete_storage(pvc_name)
        return jsonify(result), HTTPStatus.OK
    except Exception as e:
        current_app.logger.error(f"API Error deleting PVC: {str(e)}")
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR
