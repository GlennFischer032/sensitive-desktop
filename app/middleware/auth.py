"""Authentication middleware for the application."""
import functools
from typing import Callable

from flask import flash, redirect, session, url_for
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
        if "token" not in session:
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
        if "token" not in session:
            flash("Please log in to access this page", "error")
            return redirect(url_for("auth.login"))

        if not session.get("is_admin", False):
            flash("You need administrator privileges to access this page", "error")
            return redirect(url_for("index"))

        return view_func(*args, **kwargs)

    return wrapped_view
