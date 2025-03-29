import json
import logging
import os
import secrets
from datetime import datetime, timedelta

import jwt
import requests
from flask import (
    abort,
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
from app.middleware.security import rate_limit
from app.utils.decorators import admin_required, login_required

from . import auth_bp

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


@auth_bp.route("/login", methods=["GET", "POST"])
@rate_limit(requests_per_minute=5, requests_per_hour=20)  # Stricter limits for login attempts
def login():
    # Username/password authentication has been removed
    # If POST method is used, redirect to OIDC login
    if request.method == "POST":
        logger.info("Username/password authentication attempt detected - redirecting to OIDC login")
        flash(
            "Username/password authentication has been disabled. Please use e-INFRA CZ login.",
            "info",
        )
        return redirect(url_for("auth.oidc_login"))

    # For GET requests, show the login page with OIDC button only
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
        # Use the configured OIDC redirect URI instead of the request's base URL
        # This ensures we use the external URL even when the request comes to localhost
        callback_url = os.environ.get("OIDC_REDIRECT_URI", request.base_url)
        logger.info(f"Using callback URL: {callback_url}")

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
        session["username"] = data["user"]["username"]
        session["is_admin"] = data["user"]["is_admin"]
        session["email"] = data["user"]["email"]
        session["organization"] = data.get("organization")
        session["sub"] = data.get("sub")
        session.permanent = True

        logger.info(f"User {data['user']['username']} successfully authenticated via OIDC")
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
        auth_url = data.get("authorization_url") or data.get("auth_url")

        if not auth_url:
            raise ValueError("No authorization URL in response")

        logger.info("Redirecting to OIDC provider for authentication")
        return redirect(auth_url)
    except Exception as e:
        logger.error(f"OIDC login initiation failed: {str(e)}")
        flash("Failed to initiate login. Please try again.", "error")
        return redirect(url_for("auth.login"))


@auth_bp.route("/debug-login", methods=["GET", "POST"])
@rate_limit(requests_per_minute=5, requests_per_hour=20)
def debug_login():
    """Debug login route that bypasses OIDC authentication for development purposes."""
    # Only allow access if debug login is enabled
    if not current_app.config.get("DEBUG_LOGIN_ENABLED", False):
        logger.warning("Attempt to access debug login when disabled")
        abort(404)

    if request.method == "GET":
        return render_template("debug_login.html")

    # Process the form for POST requests
    try:
        data = request.get_json()
        logger.debug(f"Debug login request data: {data}")

        if not data:
            logger.error("No JSON data received in debug login request")
            return jsonify({"error": "Missing request data"}), 400

        # Extract required fields
        sub = data.get("sub")
        email = data.get("email")

        logger.debug(f"Debug login attempt with sub: {sub}")

        # Extract optional fields with defaults
        given_name = data.get("given_name", "")
        family_name = data.get("family_name", "")
        name = data.get("name") or f"{given_name} {family_name}".strip() or ""
        organization = data.get("organization", "e-INFRA")
        locale = data.get("locale", "en-US")
        email_verified = data.get("email_verified", True)

        # We only need the sub to validate user exists
        if not sub:
            logger.error("Debug login attempt with missing sub")
            return jsonify({"error": "Sub ID is required"}), 400

        # Verify if user exists with the provided sub in the database
        try:
            # Check against API that the user exists with this sub
            api_url = f"{current_app.config['API_URL']}/api/users/verify"
            logger.debug(f"Verifying user at: {api_url} with sub: {sub}")

            response = requests.get(api_url, params={"sub": sub}, timeout=5)

            logger.debug(f"Verify response status: {response.status_code}")
            if response.status_code != 200:
                logger.error(f"User verification failed for sub {sub}: {response.text}")
                return jsonify(
                    {
                        "error": "User with this sub does not exist in the database. Please ask an admin to create the user first."
                    }
                ), 404

            # Get user details from response
            user_data = response.json()
            logger.debug(f"User data from API: {user_data}")

            # Override form values with actual values from database
            username = user_data.get("username", "")
            is_admin = user_data.get("is_admin", False)

            if not username:
                logger.error(f"No username returned for sub {sub}")
                return jsonify({"error": "User data incomplete in database"}), 500

            # Generate a proper JWT token similar to what the API would return
            # Create a payload similar to what the API would generate
            exp_time = datetime.utcnow() + timedelta(hours=24)
            payload = {
                "sub": str(user_data.get("user_id")),
                "name": username,
                "iat": datetime.utcnow(),
                "exp": exp_time,
                "admin": is_admin,
            }
            # Sign it with the app's secret key
            mock_token = jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")

            # Set session variables
            session.clear()
            session["token"] = mock_token
            session["username"] = username
            session["is_admin"] = is_admin
            session["email"] = email
            session["organization"] = organization
            session["sub"] = sub
            session["given_name"] = given_name
            session["family_name"] = family_name
            session["name"] = name
            session["locale"] = locale
            session["email_verified"] = email_verified
            session["logged_in"] = True
            session["debug_login"] = True
            session.permanent = True

            logger.warning(f"Debug login used for user {username} with sub {sub}")

            # Return success response for fetch API
            return jsonify(
                {
                    "success": True,
                    "message": "Debug login successful",
                    "redirect": url_for(
                        "users.dashboard" if is_admin else "connections.view_connections"
                    ),
                }
            )

        except requests.exceptions.RequestException as e:
            logger.error(f"Error during debug login verification: {str(e)}")
            return jsonify({"error": "Error verifying user. Please try again."}), 500
    except Exception as e:
        logger.error(f"Debug login error: {str(e)}")
        return jsonify({"error": str(e)}), 500
