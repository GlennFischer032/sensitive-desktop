from clients.factory import client_factory
from flask import (
    current_app,
    flash,
    render_template,
    session,
)
from middleware.auth import token_required
from middleware.security import rate_limit

from . import storage_bp


@storage_bp.route("/")
@token_required
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
        pvcs = storage_client.list_storage(token=session["token"])

        users = []
        if session.get("is_admin"):
            users_client = client_factory.get_users_client()
            users = users_client.list_users(token=session["token"])

        current_app.logger.info(f"Retrieved {len(pvcs)} storage PVCs")
        return render_template("storage_pvcs.html", pvcs=pvcs, users=users, is_admin=session.get("is_admin", False))
    except Exception as e:
        current_app.logger.error(f"Error fetching storage PVCs: {str(e)}")
        flash(f"Error fetching storage PVCs: {str(e)}", "error")
        return render_template("storage_pvcs.html", pvcs=[])
