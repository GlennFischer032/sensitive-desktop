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
from utils.decorators import admin_required, login_required

from . import storage_bp


@storage_bp.route("/pvcs")
@login_required
@rate_limit(requests_per_minute=20)
def view_pvcs():
    """View storage PVCs management page."""
    try:
        # Fetch storage PVCs from API
        token = session.get("token")
        if not token:
            flash("Authentication required", "error")
            return redirect(url_for("auth.login"))

        api_url = f"{current_app.config['API_URL']}/api/storage-pvcs/list"
        response = requests.get(api_url, headers={"Authorization": f"Bearer {token}"}, timeout=10)

        if response.status_code != 200:
            error_message = f"Failed to fetch storage PVCs: {response.text}"
            current_app.logger.error(error_message)
            flash(error_message, "error")
            return render_template("storage_pvcs.html", pvcs=[])

        data = response.json()
        pvcs = data.get("pvcs", [])

        # Get users for access control
        users = []
        if session.get("is_admin"):
            users_url = f"{current_app.config['API_URL']}/api/users/list"
            users_response = requests.get(
                users_url, headers={"Authorization": f"Bearer {token}"}, timeout=10
            )

            if users_response.status_code == 200:
                users_data = users_response.json()
                users = users_data.get("users", [])

        current_app.logger.info(f"Retrieved {len(pvcs)} storage PVCs")
        return render_template(
            "storage_pvcs.html", pvcs=pvcs, users=users, is_admin=session.get("is_admin", False)
        )
    except Exception as e:
        current_app.logger.error(f"Error fetching storage PVCs: {str(e)}")
        flash(f"Error fetching storage PVCs: {str(e)}", "error")
        return render_template("storage_pvcs.html", pvcs=[])


@storage_bp.route("/pvcs/<int:pvc_id>/access", methods=["GET"])
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
        current_app.logger.error(f"Unexpected error getting PVC access: {str(e)}")
        return jsonify({"error": str(e)}), 500


@storage_bp.route("/pvcs/<int:pvc_id>/access", methods=["POST"])
@login_required
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
        current_app.logger.error(f"Unexpected error updating PVC access: {str(e)}")
        return jsonify({"error": str(e)}), 500


@storage_bp.route("/pvcs/<int:pvc_id>", methods=["GET"])
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

        if response.status_code != 200:
            return jsonify({"error": response.text}), response.status_code

        return jsonify(response.json())
    except Exception as e:
        current_app.logger.error(f"Error fetching PVC: {str(e)}")
        return jsonify({"error": str(e)}), 500


@storage_bp.route("/pvcs", methods=["POST"])
@login_required
def create_pvc():
    """Create a new storage PVC."""
    try:
        # Get request data
        data = request.get_json()
        if not data:
            return jsonify({"error": "No input data provided"}), 400

        # Get token
        token = session.get("token")
        if not token:
            return jsonify({"error": "Authentication required"}), 401

        # Forward request to API
        api_url = f"{current_app.config['API_URL']}/api/storage-pvcs/create"

        # Log the request data for debugging
        current_app.logger.info(f"Creating PVC with data: {data}")

        response = requests.post(
            api_url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=data,
            timeout=30,
        )

        # Return the API response as-is
        return jsonify(response.json()), response.status_code
    except Exception as e:
        current_app.logger.error(f"Error creating PVC: {str(e)}")
        return jsonify({"error": str(e)}), 500


@storage_bp.route("/api/connection/<int:pvc_id>", methods=["GET"])
@login_required
def get_pvc_connections(pvc_id):
    """Get connections using a specific PVC."""
    try:
        token = session.get("token")
        if not token:
            return jsonify({"error": "Authentication required"}), 401

        # Use the new connections endpoint instead of the connection PVCs endpoint
        api_url = f"{current_app.config['API_URL']}/api/storage-pvcs/connections/{pvc_id}"
        response = requests.get(api_url, headers={"Authorization": f"Bearer {token}"}, timeout=10)

        if response.status_code != 200:
            return jsonify({"error": response.text}), response.status_code

        return jsonify(response.json())
    except Exception as e:
        current_app.logger.error(f"Error fetching PVC connections: {str(e)}")
        return jsonify({"error": str(e)}), 500


@storage_bp.route("/api/users", methods=["GET"])
@login_required
def get_users_list():
    """Get list of users for access control."""
    try:
        token = session.get("token")
        if not token:
            return jsonify({"error": "Authentication required"}), 401

        # Fixed endpoint to match backend API
        api_url = f"{current_app.config['API_URL']}/api/users/list"
        response = requests.get(api_url, headers={"Authorization": f"Bearer {token}"}, timeout=10)

        if response.status_code != 200:
            return jsonify({"error": response.text}), response.status_code

        return jsonify(response.json())
    except Exception as e:
        current_app.logger.error(f"Error fetching users list: {str(e)}")
        return jsonify({"error": str(e)}), 500


@storage_bp.route("/api/pvc/<string:pvc_name>", methods=["DELETE"])
@login_required
def delete_pvc(pvc_name):
    """Delete a PVC by name."""
    try:
        token = session.get("token")
        if not token:
            return jsonify({"error": "Authentication required"}), 401

        api_url = f"{current_app.config['API_URL']}/api/storage-pvcs/{pvc_name}"
        response = requests.delete(
            api_url, headers={"Authorization": f"Bearer {token}"}, timeout=30
        )

        if response.status_code != 200:
            return jsonify({"error": response.text}), response.status_code

        return jsonify(response.json())
    except Exception as e:
        current_app.logger.error(f"Error deleting PVC: {str(e)}")
        return jsonify({"error": str(e)}), 500
