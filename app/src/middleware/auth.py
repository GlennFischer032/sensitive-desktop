"""Authentication middleware for the application."""
import functools
from collections.abc import Callable
from http import HTTPStatus

from clients.factory import client_factory
from flask import abort, flash, redirect, request, session, url_for


def token_required(view_func: Callable) -> Callable:
    """Decorator that redirects to login page if user is not logged in.

    Args:
        view_func: The view function to decorate

    Returns:
        Callable: The decorated function
    """

    @functools.wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if request.headers.get("Authorization"):
            token = request.headers.get("Authorization").split(" ")[1]
            user_data, status_code = client_factory.get_tokens_client().api_login(token)
            if status_code != HTTPStatus.OK:
                flash("Invalid token", "error")
                return redirect(url_for("auth.login"))
            session["username"] = user_data.get("username")
            session["is_admin"] = user_data.get("is_admin")
            session["email"] = user_data.get("email")
            session["logged_in"] = True
            session["token"] = token
            return view_func(*args, **kwargs)

        if not session.get("logged_in") or "token" not in session:
            flash("Please log in to access this page", "error")
            return redirect(url_for("auth.login"))
        session["token"] = session.get("token")
        return view_func(*args, **kwargs)

    return wrapped_view


def admin_required(view_func: Callable) -> Callable:
    """Decorator that redirects to login page if user is not an admin.

    Args:
        view_func: The view function to decorate

    Returns:
        Callable: The decorated function
    """

    @functools.wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not session.get("is_admin"):
            flash("You need administrator privileges", "error")
            return abort(403, description="You need administrator privileges")
        return view_func(*args, **kwargs)

    return wrapped_view
