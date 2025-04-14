"""OIDC Authentication Routes.

This module implements the OIDC authentication flow with PKCE support.
It handles the OIDC authorization, callback, and token exchange.
"""

from http import HTTPStatus
import logging
from typing import Any

from database.core.session import with_db_session
from flask import Blueprint, current_app, jsonify, request
from services.connections import APIError
from services.user import UserService


logger = logging.getLogger(__name__)
oidc_bp = Blueprint("oidc_bp", __name__)


@oidc_bp.route("/auth/oidc/login", methods=["GET"])
@with_db_session
def oidc_login() -> tuple[dict[str, Any], int]:
    """Initiate OIDC login flow.

    This endpoint starts the OIDC authentication flow by generating
    necessary PKCE parameters and redirecting to the OIDC provider.

    Returns:
        tuple: A tuple containing:
            - Dict with authorization URL
            - HTTP status code
    """
    try:
        # Create UserService instance and initiate OIDC login
        user_service = UserService()
        response_data = user_service.initiate_oidc_login(request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logger.error("API error in OIDC login: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logger.error("Error initiating OIDC login: %s", str(e))
        return (
            jsonify({"error": "Failed to initiate OIDC login", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@oidc_bp.route("/auth/oidc/callback", methods=["POST"])
@with_db_session
def oidc_callback() -> tuple[dict[str, Any], int]:
    """Handle OIDC callback.

    This endpoint handles the callback from the OIDC provider,
    exchanges the authorization code for tokens, and authenticates
    or creates the user in the local database.

    Returns:
        tuple: A tuple containing:
            - Dict with authentication result
            - HTTP status code
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing request data"}), HTTPStatus.BAD_REQUEST

        code = data.get("code")
        state = data.get("state")

        # Create UserService instance and process OIDC callback
        user_service = UserService()
        response_data = user_service.process_oidc_callback(
            code, state, current_app.config["SECRET_KEY"], request.db_session
        )

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logger.error("API error in OIDC callback: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logger.error("Error processing OIDC callback: %s", str(e))
        return (
            jsonify({"error": "Failed to process OIDC callback", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )
