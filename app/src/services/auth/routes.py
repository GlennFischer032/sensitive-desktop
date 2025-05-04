import logging
import os
from datetime import datetime, timedelta
from http import HTTPStatus

import jwt
from clients.factory import client_factory
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
from middleware.security import rate_limit

from . import auth_bp

logger = logging.getLogger(__name__)


@auth_bp.route("/login", methods=["GET"])
@rate_limit(requests_per_minute=15, requests_per_hour=100)
def login():
    """Login page endpoint
    This endpoint renders the login page for users to authenticate.
    ---
    tags:
      - Authentication
    responses:
      200:
        description: Login page rendered successfully
    """
    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    """Logout endpoint
    This endpoint logs out the current user and redirects to the login page.
    ---
    tags:
      - Authentication
    responses:
      302:
        description: User logged out successfully and redirected to login page
    """
    current_app.logger.debug(f"Logging out user: {session.get('username')}")
    auth_client = client_factory.get_auth_client()
    auth_client.logout()
    return redirect(url_for("auth.login"))


@auth_bp.route("/oidc/callback")
def oidc_callback():
    """Handle OIDC callback from authentication provider
    This endpoint processes the callback from the OIDC provider after user authentication.
    ---
    tags:
      - Authentication
    parameters:
      - name: code
        in: query
        type: string
        required: true
        description: Authorization code from OIDC provider
      - name: state
        in: query
        type: string
        required: true
        description: State parameter for CSRF protection
    responses:
      302:
        description: User authenticated successfully and redirected to dashboard
      400:
        description: Invalid callback parameters
      500:
        description: Authentication error
    """
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

    try:
        callback_url = os.environ.get("OIDC_REDIRECT_URI", request.base_url)
        logger.debug(f"Using callback URL: {callback_url}")

        auth_client = client_factory.get_auth_client()
        response_data, status_code = auth_client.oidc_callback(
            code=code,
            state=state,
            redirect_uri=callback_url,
        )

        if status_code != HTTPStatus.OK:
            error_message = response_data.get("error", "Unknown error occurred")
            logger.error(f"OIDC callback failed: {error_message}")
            flash("Authentication failed. Please try again.", "error")
            return redirect(url_for("auth.login"))

        data = response_data
        session.clear()
        session["token"] = data["token"]
        session["username"] = data["user"]["username"]
        session["is_admin"] = data["user"]["is_admin"]
        session["email"] = data["user"]["email"]
        session["organization"] = data.get("organization")
        session["sub"] = data.get("sub")
        session["logged_in"] = True
        session.permanent = True

        logger.debug(f"User {data['user']['username']} successfully authenticated via OIDC")
        logger.debug(f"Admin status: {data['user']['is_admin']}")
        flash("Successfully logged in", "success")

        if session["is_admin"]:
            return redirect(url_for("users.dashboard"))
        return redirect(url_for("connections.view_connections"))

    except Exception as e:
        logger.error(f"Error during OIDC callback: {str(e)}")
        flash("Error completing authentication. Please try again.", "error")
        return redirect(url_for("auth.login"))


@auth_bp.route("/oidc/login")
@rate_limit(requests_per_minute=5, requests_per_hour=20)
def oidc_login():
    """Initiate OIDC login flow using backend.
    This endpoint redirects the user to the OIDC provider for authentication.
    ---
    tags:
      - Authentication
    responses:
      302:
        description: Redirect to OIDC provider
      500:
        description: Failed to initiate OIDC login flow
        schema:
          type: object
          properties:
            error:
              type: string
              example: Failed to initiate login
    """
    try:
        auth_client = client_factory.get_auth_client()
        response_data, status_code = auth_client.oidc_login()

        if status_code != HTTPStatus.OK:
            raise ValueError("Failed to get authorization URL from backend")

        auth_url = response_data.get("authorization_url") or response_data.get("auth_url")

        if not auth_url:
            raise ValueError("No authorization URL in response")

        logger.debug("Redirecting to OIDC provider for authentication")
        return redirect(auth_url)
    except Exception as e:
        logger.error(f"OIDC login initiation failed: {str(e)}")
        flash("Failed to initiate login. Please try again.", "error")
        return redirect(url_for("auth.login"))


@auth_bp.route("/debug-login", methods=["GET", "POST"])
@rate_limit(requests_per_minute=5, requests_per_hour=20)
def debug_login():  # noqa
    """Debug login route for development purposes
    This endpoint provides a development-only method to bypass OIDC authentication.
    Only available when DEBUG mode is enabled.
    ---
    tags:
      - Debug
    methods:
      - GET
      - POST
    parameters:
      - name: body
        in: body
        schema:
          type: object
          properties:
            sub:
              type: string
              description: Subject identifier
              required: true
            email:
              type: string
              description: User email
            given_name:
              type: string
              description: User's given name
            family_name:
              type: string
              description: User's family name
            is_admin:
              type: boolean
              description: Override admin status
            organization:
              type: string
              description: User organization
    responses:
      200:
        description: Debug login successful
        schema:
          type: object
          properties:
            success:
              type: boolean
            message:
              type: string
            redirect:
              type: string
      400:
        description: Missing or invalid request data
      404:
        description: Debug login disabled or user not found
      500:
        description: Server error during login process
    """
    if not current_app.config.get("DEBUG", False):
        logger.warning("Attempt to access debug login when disabled")
        abort(404)

    if request.method == "GET":
        return render_template("debug_login.html")

    try:
        data = request.get_json()
        logger.debug(f"Debug login request data: {data}")

        if not data:
            logger.error("No JSON data received in debug login request")
            return jsonify({"error": "Missing request data"}), 400

        sub = data.get("sub")
        email = data.get("email")

        logger.debug(f"Debug login attempt with sub: {sub}")

        given_name = data.get("given_name", "")
        family_name = data.get("family_name", "")
        name = data.get("name") or f"{given_name} {family_name}".strip() or ""
        organization = data.get("organization", "e-INFRA")
        locale = data.get("locale", "en-US")
        email_verified = data.get("email_verified", True)
        override_admin = "is_admin" in data

        if not sub:
            logger.error("Debug login attempt with missing sub")
            return jsonify({"error": "Sub ID is required"}), 400

        try:
            users_client = client_factory.get_users_client()

            try:
                user_data, status_code = users_client.verify_user(sub=sub)

                logger.debug(f"Verify response status: {status_code}")
                if status_code != HTTPStatus.OK:
                    logger.error(f"User verification failed for sub {sub}")
                    return jsonify(
                        {
                            "error": "User with this sub does not exist in the database. "
                            "Please ask an admin to create the user first."
                        }
                    ), 404

                logger.debug(f"User data from API: {user_data}")

                username = user_data.get("username", "")
                is_admin = data.get("is_admin", False) if override_admin else user_data.get("is_admin", False)

                if not username:
                    logger.error(f"No username returned for sub {sub}")
                    return jsonify({"error": "User data incomplete in database"}), 500

                exp_time = datetime.utcnow() + timedelta(hours=24)
                payload = {
                    "sub": sub,
                    "name": username,
                    "iat": datetime.utcnow(),
                    "exp": exp_time,
                    "admin": is_admin,
                }
                mock_token = jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")

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

                return jsonify(
                    {
                        "success": True,
                        "message": "Debug login successful",
                        "redirect": url_for("connections.view_connections"),
                    }
                )

            except Exception as e:
                logger.error(f"Error during user verification: {str(e)}")
                return jsonify({"error": "Error verifying user. Please try again."}), 500

        except Exception as e:
            logger.error(f"Error during debug login verification: {str(e)}")
            return jsonify({"error": "Error verifying user. Please try again."}), 500
    except Exception as e:
        logger.error(f"Debug login error: {str(e)}")
        return jsonify({"error": str(e)}), 500
