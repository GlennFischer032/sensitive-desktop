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
    """View storage PVCs management page."""
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
    """Get access information for a PVC."""
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
    """Update access control for a PVC."""
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
    """Get a specific PVC."""
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
    """Create a new storage PVC."""
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
    """Get connections using a specific PVC."""
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
    """Get list of users for access control."""
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
    """Delete a PVC by name."""
    try:
        storage_client = client_factory.get_storage_client()
        result = storage_client.delete_storage(pvc_name)
        return jsonify(result)
    except Exception as e:
        current_app.logger.error(f"Error deleting PVC: {str(e)}")
        return jsonify({"error": str(e)}), 500
