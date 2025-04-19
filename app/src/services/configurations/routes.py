"""Routes for desktop configurations."""
import logging

from clients.base import APIError
from clients.factory import client_factory
from flask import flash, render_template, session
from middleware.auth import token_required

from . import configurations_bp

logger = logging.getLogger(__name__)


@configurations_bp.route("/")
@token_required
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
        configs = desktop_configs_client.list_configurations(token=session["token"])

        # Get all users for the modal form
        try:
            users_data = desktop_configs_client.get_users(token=session["token"])
            all_users = users_data.get("data", [])
        except APIError as e:
            logger.error(f"Error fetching users: {str(e)}")
            all_users = []

        return render_template("configurations.html", configurations=configs, users=all_users)
    except APIError as e:
        logger.error(f"Error listing configurations: {str(e)}")
        flash(f"Error listing configurations: {str(e)}", "error")
        return render_template("configurations.html", configurations=[])
