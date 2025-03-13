import json
import logging
import secrets

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

from . import auth_bp

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


@auth_bp.route("/login", methods=["GET", "POST"])
@rate_limit(requests_per_minute=5, requests_per_hour=20)  # Stricter limits for login attempts
def login():
    if request.method == "POST":
        # Handle both form data and JSON
        if request.is_json:
            data = request.get_json()
            username = data.get("username")
            password = data.get("password")
        else:
            username = request.form.get("username")
            password = request.form.get("password")

        logger.debug(f"Login attempt for user: {username}")

        if not username or not password:
            logger.warning("Missing username or password")
            if request.is_json:
                return {"error": "Missing required fields"}, 400
            flash("Please provide both username and password")
            return render_template("login.html")

        try:
            auth_client = client_factory.get_auth_client()
            data, status_code = auth_client.login(username, password)

            logger.debug(f"Successful login response data: {json.dumps(data, indent=2)}")
            logger.info(f"Login successful for {username}, is_admin: {session['is_admin']}")

            if session["is_admin"]:
                return redirect(url_for("users.dashboard"))
            return redirect(url_for("connections.view_connections"))

        except APIError as e:
            logger.error(f"Login failed: {e.message}")
            if request.is_json:
                return {"error": e.message}, e.status_code
            flash("Login failed. Please check your credentials.")
            return render_template("login.html")
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            if request.is_json:
                return {"error": str(e)}, 500
            flash("Login service unavailable. Please try again later.")
            return render_template("login.html")
    return render_template("login.html")


@auth_bp.route("/logout")
@login_required  # Ensure user is logged in before logging out
@rate_limit(requests_per_minute=10)  # Basic rate limiting for logout
def logout():
    current_app.logger.info(f"Logging out user: {session.get('username')}")
    auth_client = client_factory.get_auth_client()
    auth_client.logout()
    return redirect(url_for("auth.login"))


@auth_bp.route("/oidc/callback")
def oidc_callback():
    """Handle OIDC callback by forwarding to backend"""
    if "error" in request.args:
        error = request.args.get("error")
        error_description = request.args.get("error_description", "")
        logger.error(f"OIDC error: {error} - {error_description}")
        flash(f"Authentication failed: {error_description}", "error")
        return redirect(url_for("auth.login"))

    code = request.args.get("code")
    state = request.args.get("state")

    if not code or not state:
        logger.error("Missing code or state in callback")
        flash("Invalid callback parameters", "error")
        return redirect(url_for("auth.login"))

    # Forward the callback to backend using POST
    try:
        # Get the current callback URL
        callback_url = request.base_url  # This gets the full URL of the current route

        # TODO: Add OIDC callback method to auth client
        response = requests.post(
            f"{current_app.config['API_URL']}/api/auth/oidc/callback",
            json={
                "code": code,
                "state": state,
                "redirect_uri": callback_url,
            },
            timeout=10,
        )

        if response.status_code != 200:
            error_message = response.json().get("error", "Unknown error occurred")
            logger.error(f"OIDC callback failed: {error_message}")
            flash("Authentication failed. Please try again.", "error")
            return redirect(url_for("auth.login"))

        # Process successful authentication
        data = response.json()
        session.clear()
        session["token"] = data["token"]
        session["username"] = data["username"]
        session["is_admin"] = data["is_admin"]
        session["email"] = data["email"]
        session["organization"] = data.get("organization")
        session["sub"] = data.get("sub")
        session.permanent = True

        logger.info(f"User {data['username']} successfully authenticated via OIDC")
        flash("Successfully logged in", "success")

        next_url = session.pop("next_url", None)
        if session["is_admin"]:
            return redirect(next_url or url_for("users.dashboard"))
        return redirect(next_url or url_for("connections.view_connections"))

    except requests.exceptions.RequestException as e:
        logger.error(f"Error during OIDC callback: {str(e)}")
        flash("Error completing authentication. Please try again.", "error")
        return redirect(url_for("auth.login"))


@auth_bp.route("/oidc/login")
@rate_limit(requests_per_minute=5, requests_per_hour=20)
def oidc_login():
    """Initiate OIDC login flow using backend."""
    try:
        # TODO: Add OIDC login method to auth client
        response = requests.get(f"{current_app.config['API_URL']}/api/auth/oidc/login", timeout=5)

        if response.status_code != 200:
            raise ValueError("Failed to get authorization URL from backend")

        data = response.json()
        auth_url = data["auth_url"]

        logger.info("Redirecting to OIDC provider for authentication")
        return redirect(auth_url)
    except Exception as e:
        logger.error(f"OIDC login initiation failed: {str(e)}")
        flash("Failed to initiate login. Please try again.", "error")
        return redirect(url_for("auth.login"))
