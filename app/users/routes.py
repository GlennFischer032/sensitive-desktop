"""Routes for user management module."""
import logging
from typing import Dict

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

from app.clients.base import APIError
from app.clients.factory import client_factory
from app.middleware.auth import admin_required
from app.middleware.security import rate_limit
from app.utils.decorators import login_required

from . import users_bp


@users_bp.route("/")
@login_required
def view_users():
    """Display users list (admin only)."""
    # Check if user is admin
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


@users_bp.route("/detail/<username>")
@login_required
@admin_required
def user_detail(username):
    try:
        current_app.logger.info(f"Fetching details for user: {username}")
        users_client = client_factory.get_users_client()
        user = users_client.get_user(username)

        # Get user's connections if available
        try:
            connections_client = client_factory.get_connections_client()
            user_connections = connections_client.list_connections(filter_by_user=username)
        except Exception as e:
            current_app.logger.warning(f"Could not fetch connections for user {username}: {str(e)}")
            user_connections = []

        return render_template("user_detail.html", user=user, user_connections=user_connections)
    except APIError as e:
        current_app.logger.error(f"Error fetching user details: {e.message}")
        flash(f"Failed to fetch user details: {e.message}", "error")
        return redirect(url_for("users.view_users"))
    except Exception as e:
        current_app.logger.error(f"Error fetching user details: {str(e)}")
        flash(f"Error fetching user details: {str(e)}", "error")
        return redirect(url_for("users.view_users"))


@users_bp.route("/add", methods=["GET", "POST"])
@login_required
@admin_required
@rate_limit(requests_per_minute=10)
def add_user():
    if request.method == "POST":
        current_app.logger.info("=== add_user route accessed ===")
        current_app.logger.info(f"Request method: {request.method}")
        current_app.logger.info(f"Form data: {request.form}")

        username = request.form.get("username")
        is_admin = request.form.get("is_admin") == "true"
        sub = request.form.get("sub")

        if not username or not sub:
            flash("Username and OIDC Subject Identifier are required", "error")
            return render_template("add_user.html")

        data = {"username": username, "is_admin": is_admin, "sub": sub}

        try:
            current_app.logger.info("Adding new user...")
            current_app.logger.info(f"User data: {data}")

            users_client = client_factory.get_users_client()

            users_client.add_user(**data)

            flash(
                "User added successfully. User information will be filled from OIDC during their first login.",
                "success",
            )
            return redirect(url_for("users.view_users"))
        except APIError as e:
            current_app.logger.error(f"Failed to add user: {e.message}")
            if e.details:
                # Handle validation errors
                error_messages = []
                for field, errors in e.details.items():
                    for error in errors:
                        error_messages.append(f"{field.title()}: {error}")
                flash("\n".join(error_messages), "error")
            else:
                flash(f"Failed to add user: {e.message}", "error")
        except Exception as e:
            current_app.logger.error(f"Unexpected error: {str(e)}")
            flash(f"Error: {str(e)}", "error")
        return render_template("add_user.html")
    return render_template("add_user.html")


@users_bp.route("/delete/<username>", methods=["POST"])
@login_required
@admin_required
def delete_user(username):
    try:
        current_app.logger.info(f"Attempting to delete user: {username}")
        if username == session.get("username"):
            flash("Cannot delete your own account")
            return redirect(url_for("users.view_users"))

        users_client = client_factory.get_users_client()
        users_client.delete_user(username)

        flash("User deleted successfully")
    except APIError as e:
        current_app.logger.error(f"Failed to delete user: {e.message}")
        flash(f"Failed to delete user: {e.message}")
    except Exception as e:
        current_app.logger.error(f"Error deleting user: {str(e)}")
        flash(f"Error: {str(e)}")

    return redirect(url_for("users.view_users"))


@users_bp.route("/dashboard")
@login_required
@admin_required
@rate_limit(requests_per_minute=30)
def dashboard():
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


@users_bp.route("/remove/<username>", methods=["POST"])
@login_required
@admin_required
@rate_limit(requests_per_minute=10)
def remove_user(username):
    try:
        # Prevent removing self
        if username == session.get("username"):
            flash("Cannot remove your own account")
            return redirect(url_for("users.dashboard"))

        users_client = client_factory.get_users_client()
        users_client.delete_user(username)

        flash("User removed successfully")
    except APIError as e:
        current_app.logger.error(f"Failed to remove user: {e.message}")
        flash(f"Failed to remove user: {e.message}")
    except Exception as e:
        current_app.logger.error(f"Error removing user: {str(e)}")
        flash(f"Error removing user: {str(e)}")

    # If it's an AJAX request, return JSON response
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return {"status": "success"}, 200

    return redirect(url_for("users.dashboard"))


@users_bp.route("/update/<username>", methods=["POST"])
@login_required
@admin_required
def update_user(username):
    try:
        current_app.logger.info(f"Updating user: {username}")
        data = request.get_json()

        if not data:
            return jsonify({"error": "Missing request data"}), 400

        current_app.logger.info(f"Update data: {data}")

        users_client = client_factory.get_users_client()
        users_client.update_user(username, **data)

        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"message": "User updated successfully"}), 200

        flash(f"User {username} updated successfully", "success")
        return redirect(url_for("users.user_detail", username=username))

    except APIError as e:
        current_app.logger.error(f"Failed to update user: {e.message}")
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"error": e.message}), e.status_code

        flash(f"Failed to update user: {e.message}", "error")
        return redirect(url_for("users.user_detail", username=username))

    except Exception as e:
        current_app.logger.error(f"Error updating user: {str(e)}")
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"error": str(e)}), 500

        flash(f"Error updating user: {str(e)}", "error")
        return redirect(url_for("users.user_detail", username=username))
