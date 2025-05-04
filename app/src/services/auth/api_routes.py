"""API routes for authentication.

This module provides API endpoints for authentication operations, separate from UI routes.
"""

import logging
from http import HTTPStatus

from clients.factory import client_factory
from flask import jsonify, session
from middleware.auth import token_required
from services.auth.auth import AuthError, is_authenticated, logout

from . import auth_api_bp

logger = logging.getLogger(__name__)


@auth_api_bp.route("/status", methods=["GET"])
def auth_status():
    """Get the current authentication status.
    ---
    tags:
      - Unauthenticated Routes
    responses:
      200:
        description: Current authentication status
        schema:
          type: object
          properties:
            authenticated:
              type: boolean
            user:
              type: object
              properties:
                username:
                  type: string
                is_admin:
                  type: boolean
                email:
                  type: string
    """
    authenticated = session.get("logged_in", False) and "token" in session

    if authenticated:
        user_data = {
            "username": session.get("username"),
            "is_admin": session.get("is_admin", False),
            "email": session.get("email"),
        }
        return jsonify({"authenticated": True, "user": user_data}), HTTPStatus.OK

    return jsonify({"authenticated": False}), HTTPStatus.OK


@auth_api_bp.route("/refresh", methods=["POST"])
@token_required
def api_refresh_token():
    """Refresh authentication token.
    ---
    tags:
      - Login Required Routes
    responses:
      200:
        description: Token refreshed successfully
      401:
        description: Not authenticated or token refresh failed
      503:
        description: Network or service error
    """
    try:
        # Check if user is authenticated
        if not is_authenticated():
            return jsonify({"error": "Not authenticated"}), HTTPStatus.UNAUTHORIZED

        # Get the token from session
        token = session.get("token")
        if not token:
            return jsonify({"error": "No token in session"}), HTTPStatus.UNAUTHORIZED

        # Get the auth client and refresh token
        auth_client = client_factory.get_auth_client()
        data, status_code = auth_client.refresh_token(token=token)

        # Handle successful response
        if status_code == HTTPStatus.OK:
            # Update session token
            session["token"] = data["token"]
            return jsonify(data), HTTPStatus.OK

        # Handle error response
        return jsonify(data), status_code

    except AuthError as e:
        # If token refresh fails, clear session
        logout()
        return jsonify({"error": str(e)}), e.status_code
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        logout()
        return jsonify({"error": "Network error"}), HTTPStatus.SERVICE_UNAVAILABLE
