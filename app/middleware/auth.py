"""Authentication middleware for the application."""
import functools
from typing import Callable

from flask import current_app, flash, jsonify, redirect, request, session, url_for
from werkzeug.wrappers import Response


def login_required(view_func: Callable) -> Callable:
    """Decorator that redirects to login page if user is not logged in.

    Args:
        view_func: The view function to decorate

    Returns:
        Callable: The decorated function
    """

    @functools.wraps(view_func)
    def wrapped_view(*args, **kwargs):
        # Skip authentication if in testing mode and flag is set
        if current_app.config.get("TESTING") and current_app.config.get("SKIP_AUTH_FOR_TESTING"):
            # Ensure session is properly initialized for testing
            if "logged_in" not in session:
                session["logged_in"] = True
                session["token"] = current_app.config.get("TEST_TOKEN", "dummy-token")
                session["username"] = "test-user"
                session["is_admin"] = True
            return view_func(*args, **kwargs)

        if not session.get("logged_in") or "token" not in session:
            error_message = "Authentication required"

            # Use proper content negotiation based on Accept header
            if request.is_json or "application/json" in request.headers.get("Accept", ""):
                return jsonify({"success": False, "error": error_message}), 401

            flash("Please log in to access this page", "error")
            return redirect(url_for("auth.login"))

        return view_func(*args, **kwargs)

    return wrapped_view


def admin_required(view_func: Callable) -> Callable:
    """Decorator that redirects to home page if user is not an admin.

    Args:
        view_func: The view function to decorate

    Returns:
        Callable: The decorated function
    """

    @functools.wraps(view_func)
    def wrapped_view(*args, **kwargs) -> Response:
        # Skip authentication if in testing mode and flag is set
        if current_app.config.get("TESTING") and current_app.config.get("SKIP_AUTH_FOR_TESTING"):
            # Ensure session is properly initialized for testing
            if "logged_in" not in session:
                session["logged_in"] = True
                session["token"] = current_app.config.get("TEST_TOKEN", "dummy-token")
                session["username"] = "test-user"
                session["is_admin"] = True
            return view_func(*args, **kwargs)

        # First check if the user is logged in
        if not session.get("logged_in") or "token" not in session:
            error_message = "Authentication required"

            # Use proper content negotiation based on Accept header
            if request.is_json or "application/json" in request.headers.get("Accept", ""):
                return jsonify({"success": False, "error": error_message}), 401

            flash("Please log in to access this page", "error")
            return redirect(url_for("auth.login"))

        # Then check if the user is an admin
        if not session.get("is_admin", False):
            error_message = "Administrator privileges required"

            # Use proper content negotiation based on Accept header
            if request.is_json or "application/json" in request.headers.get("Accept", ""):
                return jsonify({"success": False, "error": error_message}), 403

            flash("You need administrator privileges to access this page", "error")
            return redirect(url_for("index"))

        return view_func(*args, **kwargs)

    return wrapped_view


def simulate_login(session_obj, token, is_admin=False, username="test_user"):
    """Simulate login for testing purposes.

    Args:
        session_obj: The session object to modify
        token: The token to set
        is_admin: Whether the user is an admin
        username: The username to set

    Returns:
        None
    """
    # Ensure we have all necessary session keys for testing
    session_obj["token"] = token
    session_obj["is_admin"] = is_admin
    session_obj["username"] = username
    session_obj["logged_in"] = True
    session_obj["user_id"] = 1 if not is_admin else 2  # Set a dummy user ID
    session_obj.permanent = True  # Ensure session persists
