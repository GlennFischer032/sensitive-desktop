"""Routes for user management module."""

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
from app.middleware.auth import admin_required, login_required
from app.middleware.security import rate_limit

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


@users_bp.route("/detail/<username>")
@login_required
@admin_required
def user_detail(username):
    """API endpoint to get user details for the modal view.
    This endpoint retrieves detailed information about a specific user.
    ---
    tags:
      - Users
    parameters:
      - name: username
        in: path
        type: string
        required: true
        description: Username of the user to get details for
    responses:
      200:
        description: User details retrieved successfully
        schema:
          type: object
          properties:
            user:
              type: object
              description: User details
            user_connections:
              type: array
              description: List of user's connections
      404:
        description: User not found
      500:
        description: Error fetching user details
    """
    try:
        current_app.logger.info(f"API: Fetching details for user: {username}")
        users_client = client_factory.get_users_client()
        user = users_client.get_user(username)

        # Get user's connections if available
        try:
            connections_client = client_factory.get_connections_client()
            user_connections = connections_client.list_connections(username)
        except Exception as e:
            current_app.logger.warning(f"Could not fetch connections for user {username}: {str(e)}")
            user_connections = []

        return jsonify({"user": user, "user_connections": user_connections}), 200
    except APIError as e:
        current_app.logger.error(f"API Error fetching user details: {e.message}")
        return jsonify({"error": f"Failed to fetch user details: {e.message}"}), e.status_code
    except Exception as e:
        current_app.logger.error(f"API Error fetching user details: {str(e)}")
        return jsonify({"error": f"Error fetching user details: {str(e)}"}), 500


@users_bp.route("/add", methods=["GET", "POST"])
@login_required
@admin_required
def add_user():
    """Add a new user to the system.
    This endpoint allows administrators to add new users to the system.
    ---
    tags:
      - Users
    methods:
      - GET
      - POST
    parameters:
      - name: username
        in: formData
        type: string
        required: true
        description: Username for the new user
      - name: is_admin
        in: formData
        type: string
        required: false
        description: Whether the new user is an administrator ("true" or "false")
      - name: sub
        in: formData
        type: string
        required: true
        description: OIDC Subject Identifier
    responses:
      201:
        description: User created successfully
        schema:
          type: object
          properties:
            message:
              type: string
            username:
              type: string
      400:
        description: Invalid input parameters
      500:
        description: Error creating user
    """
    if request.method == "POST":
        current_app.logger.info("=== add_user route accessed ===")
        current_app.logger.info(f"Request method: {request.method}")
        current_app.logger.info(f"Form data: {request.form}")

        username = request.form.get("username")
        is_admin = request.form.get("is_admin") == "true"
        sub = request.form.get("sub")

        if not username or not sub:
            return _handle_missing_required_fields()

        data = {"username": username, "is_admin": is_admin, "sub": sub}

        try:
            return _create_user(data)
        except APIError as e:
            return _handle_api_error(e, username)
        except Exception as e:
            return _handle_unexpected_error(e)

    # For GET requests, redirect to the users page where the modal is available
    return redirect(url_for("users.view_users"))


def _handle_missing_required_fields():
    """Handle missing required fields for user creation."""
    error_msg = "Username and OIDC Subject Identifier are required"

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"error": error_msg}), 400

    flash(error_msg, "error")
    return redirect(url_for("users.view_users"))


def _create_user(data):
    """Create a new user with the provided data."""
    current_app.logger.info("Adding new user...")
    current_app.logger.info(f"User data: {data}")

    users_client = client_factory.get_users_client()
    users_client.add_user(**data)

    success_msg = "User added successfully. User information will be filled from OIDC during their first login."

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify(
            {
                "message": success_msg,
                "username": data["username"],
            }
        ), 201

    flash(success_msg, "success")
    return redirect(url_for("users.view_users"))


def _handle_api_error(e):
    """Handle API error during user operations."""
    current_app.logger.error(f"Failed to add user: {e.message}")

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        if e.details:
            return jsonify({"error": e.message, "details": e.details}), e.status_code
        return jsonify({"error": e.message}), e.status_code

    if e.details:
        # Handle validation errors
        error_messages = _format_validation_errors(e.details)
        flash("\n".join(error_messages), "error")
    else:
        flash(f"Failed to add user: {e.message}", "error")

    return redirect(url_for("users.view_users"))


def _format_validation_errors(error_details):
    """Format validation errors from API response."""
    error_messages = []
    for field, errors in error_details.items():
        for error in errors:
            error_messages.append(f"{field.title()}: {error}")
    return error_messages


def _handle_unexpected_error(e):
    """Handle unexpected error during user operations."""
    current_app.logger.error(f"Unexpected error: {str(e)}")

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"error": str(e)}), 500

    flash(f"Error: {str(e)}", "error")
    return redirect(url_for("users.view_users"))


@users_bp.route("/delete/<username>", methods=["POST"])
@login_required
@admin_required
def delete_user(username):  # noqa
    """Delete a user from the system.
    This endpoint allows administrators to delete a user from the system.
    ---
    tags:
      - Users
    methods:
      - POST
    parameters:
      - name: username
        in: path
        type: string
        required: true
        description: Username of the user to delete
    responses:
      200:
        description: User deleted successfully
        schema:
          type: object
          properties:
            message:
              type: string
      400:
        description: Invalid request or cannot delete own account
      404:
        description: User not found
      500:
        description: Error deleting user
    """
    try:
        current_app.logger.info(f"Attempting to delete user: {username}")
        if username == session.get("username"):
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"error": "Cannot delete your own account"}), 400
            flash("Cannot delete your own account")
            return redirect(url_for("users.view_users"))

        users_client = client_factory.get_users_client()
        users_client.delete_user(username)

        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"message": "User deleted successfully"}), 200

        flash("User deleted successfully")
    except APIError as e:
        current_app.logger.error(f"Failed to delete user: {e.message}")
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"error": e.message}), e.status_code
        flash(f"Failed to delete user: {e.message}")
    except Exception as e:
        current_app.logger.error(f"Error deleting user: {str(e)}")
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"error": str(e)}), 500
        flash(f"Error: {str(e)}")

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"error": "Failed to delete user"}), 500

    return redirect(url_for("users.view_users"))


@users_bp.route("/dashboard")
@login_required
@admin_required
@rate_limit(requests_per_minute=30)
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
