"""API Token Routes.

This module implements routes for managing API tokens for admin users.
These tokens can be used for API authentication when using external tools.
"""

from datetime import datetime
from http import HTTPStatus
import logging
from typing import Any

from core.auth import admin_required, token_required
from database.core.session import get_db_session
from database.repositories.token import TokenRepository
from flask import Blueprint, current_app, jsonify, request
import jwt
from pydantic import ValidationError
from schemas.token import Token, TokenCreate, TokenResponse


logger = logging.getLogger(__name__)
token_bp = Blueprint("token_bp", __name__)


@token_bp.route("/api/tokens", methods=["POST"])
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
        if not data:
            return jsonify({"error": "Missing request data"}), HTTPStatus.BAD_REQUEST

        try:
            token_data = TokenCreate(**data)
        except ValidationError as e:
            return jsonify({"error": str(e)}), HTTPStatus.BAD_REQUEST
        current_user = request.current_user

        with get_db_session() as session:
            token_repo = TokenRepository(session)
            token = token_repo.create_token(
                name=token_data.name,
                description=token_data.description,
                expires_in_days=token_data.expires_in_days,
                created_by=current_user.username,
            )

            # Generate JWT token with custom expiration
            payload = {
                "sub": f"token:{token.token_id}",  # Prefix to distinguish from user IDs
                "name": current_user.username,
                "token_id": token.token_id,
                "iat": datetime.utcnow(),
                "exp": token.expires_at,
                "admin": current_user.is_admin,  # Preserve admin privileges
            }

            token_jwt = jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")

            # Create response object
            response = TokenResponse(
                token=token_jwt,
                token_id=token.token_id,
                name=token.name,
                expires_at=token.expires_at,
                created_by=current_user.username,
            )

            return jsonify(response.model_dump()), HTTPStatus.CREATED

    except Exception as e:
        logger.error("Failed to create API token: %s", str(e))
        return (
            jsonify({"error": "Failed to create API token", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@token_bp.route("/api/tokens", methods=["GET"])
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

        with get_db_session() as session:
            token_repo = TokenRepository(session)
            tokens = token_repo.get_tokens_for_user(current_user.username)

            # Convert to Pydantic models for validation and to format dates correctly
            token_list = [Token.model_validate(token) for token in tokens]

            return jsonify({"tokens": [t.model_dump() for t in token_list]}), HTTPStatus.OK

    except Exception as e:
        logger.error("Failed to list API tokens: %s", str(e))
        return (
            jsonify({"error": "Failed to list API tokens", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@token_bp.route("/api/tokens/<token_id>", methods=["DELETE"])
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
        with get_db_session() as session:
            token_repo = TokenRepository(session)
            token_repo.revoke_token(token_id)

        return jsonify({"message": "Token successfully revoked"}), HTTPStatus.OK

    except Exception as e:
        logger.error("Failed to revoke API token: %s", str(e))
        return (
            jsonify({"error": "Failed to revoke API token", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )
