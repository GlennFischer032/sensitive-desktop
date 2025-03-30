from datetime import datetime
from functools import wraps

import jwt
from flask import abort, current_app, flash, redirect, request, session, url_for


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "token" not in session:
            flash("Please log in to access this page")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("is_admin", False):
            flash("Administrator privileges required", "error")
            return redirect(url_for("index"))
        return f(*args, **kwargs)

    return decorated_function
