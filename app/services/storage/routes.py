from http import HTTPStatus

import requests
from flask import (
    current_app,
    flash,
    jsonify,
    render_template,
    request,
    session,
)

from app.clients.base import APIError
from app.clients.factory import client_factory
from app.middleware.security import rate_limit
from app.middleware.auth import admin_required, login_required

from . import storage_bp


@storage_bp.route("/")
@login_required
@rate_limit(requests_per_minute=20)
def view_pvcs():
    """View storage PVCs management page.
    This endpoint displays all storage PVCs available to the user.
    ---
    tags:
      - Storage
    responses:
      200:
        description: PVCs displayed successfully
      500:
        description: Error fetching storage PVCs
    """
    try:
        storage_client = client_factory.get_storage_client()
        pvcs = storage_client.list_storage()

        users = []
        if session.get("is_admin"):
            users_client = client_factory.get_users_client()
            users = users_client.list_users()

        current_app.logger.info(f"Retrieved {len(pvcs)} storage PVCs")
        return render_template("storage_pvcs.html", pvcs=pvcs, users=users, is_admin=session.get("is_admin", False))
    except Exception as e:
        current_app.logger.error(f"Error fetching storage PVCs: {str(e)}")
        flash(f"Error fetching storage PVCs: {str(e)}", "error")
        return render_template("storage_pvcs.html", pvcs=[])


@storage_bp.route("/pvc/access/<int:pvc_id>", methods=["GET"])
@login_required
def get_pvc_access(pvc_id):
    """Get access information for a PVC.
    This endpoint retrieves the access control information for a specific PVC.
    ---
    tags:
      - Storage
    parameters:
      - name: pvc_id
        in: path
        type: integer
        required: true
        description: ID of the PVC to get access information for
    responses:
      200:
        description: PVC access information retrieved successfully
      404:
        description: PVC not found
      500:
        description: Server error
    """
    try:
        storage_client = client_factory.get_storage_client()
        data = storage_client.get_pvc_access(pvc_id)
        return jsonify(data)
    except APIError as e:
        current_app.logger.error(f"Error getting PVC access: {str(e)}")
        return jsonify({"error": str(e)}), e.status_code
    except Exception as e:
        current_app.logger.error(f"Error getting PVC access: {str(e)}")
        return jsonify({"error": str(e)}), 500


@storage_bp.route("/pvc/access/<int:pvc_id>", methods=["POST"])
@login_required
@admin_required
def update_pvc_access(pvc_id):
    """Update access control for a PVC.
    This endpoint allows administrators to modify access control settings for a PVC.
    ---
    tags:
      - Storage
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
            return jsonify({"error": "No data provided"}), 400

        is_public = data.get("is_public", False)
        allowed_users = data.get("allowed_users", [])

        storage_client = client_factory.get_storage_client()
        result = storage_client.update_pvc_access(pvc_id, is_public, allowed_users)
        return jsonify(result)
    except APIError as e:
        current_app.logger.error(f"Error updating PVC access: {str(e)}")
        return jsonify({"error": str(e)}), e.status_code
    except Exception as e:
        current_app.logger.error(f"Error updating PVC access: {str(e)}")
        return jsonify({"error": str(e)}), 500


@storage_bp.route("/pvc/<int:pvc_id>", methods=["GET"])
@login_required
def get_pvc(pvc_id):
    """Get a specific PVC.
    This endpoint retrieves detailed information about a specific PVC.
    ---
    tags:
      - Storage
    parameters:
      - name: pvc_id
        in: path
        type: integer
        required: true
        description: ID of the PVC to retrieve
    responses:
      200:
        description: PVC information retrieved successfully
      401:
        description: Authentication required
      404:
        description: PVC not found
      500:
        description: Server error
    """
    try:
        token = session.get("token")
        if not token:
            return jsonify({"error": "Authentication required"}), 401

        # The ID-based endpoint in the backend uses a numeric ID, not the name
        api_url = f"{current_app.config['API_URL']}/api/storage-pvcs/{pvc_id}"
        response = requests.get(api_url, headers={"Authorization": f"Bearer {token}"}, timeout=10)

        if response.status_code != HTTPStatus.OK:
            return jsonify({"error": response.text}), response.status_code

        return jsonify(response.json())
    except Exception as e:
        current_app.logger.error(f"Error fetching PVC: {str(e)}")
        return jsonify({"error": str(e)}), 500


@storage_bp.route("/pvc", methods=["POST"])
@login_required
@admin_required
def create_pvc():
    """Create a new storage PVC.
    This endpoint allows administrators to create a new storage PVC.
    ---
    tags:
      - Storage
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
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
      400:
        description: Invalid request data
      500:
        description: Server error
    """
    try:
        # Get request data
        data = request.get_json()
        if not data:
            return jsonify({"error": "No input data provided"}), 400

        storage_client = client_factory.get_storage_client()
        pvc = storage_client.create_storage(**data)

        # Return the API response as-is
        return pvc, 201
    except Exception as e:
        current_app.logger.error(f"Error creating PVC: {str(e)}")
        return jsonify({"error": str(e)}), 500


@storage_bp.route("/pvc/connections/<int:pvc_id>", methods=["GET"])
@login_required
def get_pvc_connections(pvc_id):
    """Get connections using a specific PVC.
    This endpoint retrieves all desktop connections that are using a specific PVC.
    ---
    tags:
      - Storage
    parameters:
      - name: pvc_id
        in: path
        type: integer
        required: true
        description: ID of the PVC to get connections for
    responses:
      200:
        description: PVC connections retrieved successfully
      404:
        description: PVC not found
      500:
        description: Server error
    """
    try:
        storage_client = client_factory.get_storage_client()
        connections = storage_client.get_pvc_connections(pvc_id)
        return jsonify(connections)
    except Exception as e:
        current_app.logger.error(f"Error fetching PVC connections: {str(e)}")
        return jsonify({"error": str(e)}), 500


@storage_bp.route("/users", methods=["GET"])
@login_required
def get_users_list():
    """Get list of users for access control.
    This endpoint retrieves a list of all users for setting up PVC access control.
    ---
    tags:
      - Storage
      - Users
    responses:
      200:
        description: Users list retrieved successfully
      500:
        description: Server error
    """
    try:
        users_client = client_factory.get_users_client()
        users = users_client.list_users()
        return jsonify(users)
    except Exception as e:
        current_app.logger.error(f"Error fetching users list: {str(e)}")
        return jsonify({"error": str(e)}), 500


@storage_bp.route("/pvc/<string:pvc_name>", methods=["DELETE"])
@login_required
@admin_required
def delete_pvc(pvc_name):
    """Delete a PVC by name.
    This endpoint allows administrators to delete a storage PVC.
    ---
    tags:
      - Storage
    parameters:
      - name: pvc_name
        in: path
        type: string
        required: true
        description: Name of the PVC to delete
    responses:
      200:
        description: PVC deleted successfully
      404:
        description: PVC not found
      500:
        description: Server error
    """
    try:
        storage_client = client_factory.get_storage_client()
        result = storage_client.delete_storage(pvc_name)
        return jsonify(result)
    except Exception as e:
        current_app.logger.error(f"Error deleting PVC: {str(e)}")
        return jsonify({"error": str(e)}), 500
