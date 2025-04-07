"""Routes for user management module."""

from flask import (
    current_app,
    flash,
    redirect,
    render_template,
    session,
    url_for,
)

from app.clients.base import APIError
from app.clients.factory import client_factory
from app.middleware.auth import admin_required, login_required

from . import users_bp


@users_bp.route("/")
@login_required
@admin_required
def view_users():
    """Display users list (admin only).
    This endpoint shows a page with all registered users. Only accessible to administrators.
    ---
    tags:
      - Users
    responses:
      200:
        description: Users list displayed successfully
      403:
        description: Forbidden - User is not an administrator
      500:
        description: Error fetching users
    """
    if not session.get("is_admin", False):
        flash("You need administrator privileges to access this page", "error")
        return redirect(url_for("connections.view_connections"))

    try:
        current_app.logger.info("Fetching users from API...")
        users_client = client_factory.get_users_client()
        users = users_client.list_users()

        current_app.logger.info(f"Found {len(users)} users")
        return render_template("users.html", users=users)
    except APIError as e:
        current_app.logger.error(f"Error fetching users: {e.message}")
        flash(f"Failed to fetch users: {e.message}")
        return render_template("users.html", users=[])
    except Exception as e:
        current_app.logger.error(f"Error fetching users: {str(e)}")
        flash(f"Error fetching users: {str(e)}")
        return render_template("users.html", users=[])


@users_bp.route("/dashboard")
@login_required
@admin_required
def dashboard():
    """Admin dashboard page.
    This endpoint displays the administrator dashboard with system overview.
    ---
    tags:
      - Users
      - Dashboard
    responses:
      200:
        description: Dashboard displayed successfully
      403:
        description: Forbidden - User is not an administrator
      500:
        description: Error fetching dashboard data
    """
    try:
        users_client = client_factory.get_users_client()
        users = users_client.list_users()

        return render_template("dashboard.html", users=users)
    except APIError as e:
        current_app.logger.error(f"Error fetching users: {e.message}")
        flash(f"Failed to fetch users list: {e.message}")
        return render_template("dashboard.html", users=[])
    except Exception as e:
        current_app.logger.error(f"Error fetching users: {str(e)}")
        flash("Error fetching users list")
        return render_template("dashboard.html", users=[])
