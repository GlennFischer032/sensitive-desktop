import requests
from flask import (
    current_app,
    flash,
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

from . import users_bp


@users_bp.route("/")
@login_required
@admin_required
def view_users():
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
        email = request.form.get("email")
        organization = request.form.get("organization")
        password = request.form.get("password")
        is_admin = request.form.get("is_admin") == "true"
        sub = request.form.get("sub")  # Get OIDC subject identifier

        if not username or not email:
            flash("Username and email are required")
            return render_template("add_user.html")

        data = {
            "username": username,
            "email": email,
            "organization": organization,
            "is_admin": is_admin,
        }

        if sub:
            data["sub"] = sub

        if password:
            data["password"] = password

        try:
            current_app.logger.info("Adding new user...")
            current_app.logger.info(f"User data: {data}")

            users_client = client_factory.get_users_client()

            user_params = {
                "username": username,
                "is_admin": is_admin,
                "email": email,
                "organization": organization,
            }

            if sub:
                user_params["sub"] = sub

            if password:
                user_params["password"] = password

            users_client.add_user(**user_params)

            flash("User added successfully", "success")
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
