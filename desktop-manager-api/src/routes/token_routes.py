"""API Token Routes.

This module implements routes for managing API tokens for admin users.
These tokens can be used for API authentication when using external tools.
"""

from http import HTTPStatus
import logging
from typing import Any

from core.auth import admin_required, token_required
from database.core.session import with_db_session
from flask import Blueprint, jsonify, request
from services.connections import APIError
from services.token import TokenService


logger = logging.getLogger(__name__)
token_bp = Blueprint("token_bp", __name__)


@token_bp.route("/api/tokens", methods=["POST"])
@with_db_session
@token_required
@admin_required
def create_token() -> tuple[dict[str, Any], int]:
    """Create a new API token.

    This endpoint allows admin users to create tokens with custom expiration.

    Returns:
        tuple: A tuple containing:
            - Dict with the token details and JWT token
            - HTTP status code
    """
    try:
        # Get request data and validate with Pydantic model
        data = request.get_json()
        current_user = request.current_user

        # Create service instance and create token
        token_service = TokenService()
        response_data = token_service.create_token(data, current_user, request.db_session)

        return jsonify(response_data), HTTPStatus.CREATED

    except APIError as e:
        logger.error("API error in create_token: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logger.error("Failed to create API token: %s", str(e))
        return (
            jsonify({"error": "Failed to create API token", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@token_bp.route("/api/tokens", methods=["GET"])
@with_db_session
@token_required
@admin_required
def list_tokens() -> tuple[dict[str, Any], int]:
    """List all tokens for the current admin user.

    Returns:
        tuple: A tuple containing:
            - Dict with list of tokens
            - HTTP status code
    """
    try:
        current_user = request.current_user

        # Create service instance and list tokens
        token_service = TokenService()
        response_data = token_service.list_tokens(current_user, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logger.error("API error in list_tokens: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logger.error("Failed to list API tokens: %s", str(e))
        return (
            jsonify({"error": "Failed to list API tokens", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@token_bp.route("/api/tokens/<token_id>", methods=["DELETE"])
@with_db_session
@token_required
@admin_required
def revoke_token(token_id: str) -> tuple[dict[str, Any], int]:
    """Revoke (delete) a token.

    Args:
        token_id: The unique ID of the token to revoke

    Returns:
        tuple: A tuple containing:
            - Dict with success message
            - HTTP status code
    """
    try:
        # Create service instance and revoke token
        token_service = TokenService()
        response_data = token_service.revoke_token(token_id, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logger.error("API error in revoke_token: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logger.error("Failed to revoke API token: %s", str(e))
        return (
            jsonify({"error": "Failed to revoke API token", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )
