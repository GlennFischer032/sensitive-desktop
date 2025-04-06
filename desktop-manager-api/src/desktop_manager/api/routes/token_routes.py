"""API Token Routes.

This module implements routes for managing API tokens for admin users.
These tokens can be used for API authentication when using external tools.
"""

from datetime import datetime, timedelta
from http import HTTPStatus
import logging
import secrets
from typing import Any, Dict, Tuple

from flask import Blueprint, current_app, jsonify, request
import jwt
from pydantic import ValidationError

from desktop_manager.api.models.token import Token, TokenCreate, TokenResponse
from desktop_manager.clients.factory import client_factory
from desktop_manager.core.auth import admin_required, token_required


logger = logging.getLogger(__name__)
token_bp = Blueprint("token_bp", __name__)


@token_bp.route("/api/tokens", methods=["POST"])
@token_required
@admin_required
def create_token() -> Tuple[Dict[str, Any], int]:
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

        # Generate unique token_id
        token_id = secrets.token_urlsafe(32)

        # Calculate expiration date
        expires_at = datetime.utcnow() + timedelta(days=token_data.expires_in_days)

        # Get current user
        current_user = request.current_user

        # Store token in database
        db_client = client_factory.get_database_client()
        insert_query = """
        INSERT INTO api_tokens
        (token_id, name, description, expires_at, created_by)
        VALUES (:token_id, :name, :description, :expires_at, :created_by)
        RETURNING id
        """

        result, _ = db_client.execute_query(
            insert_query,
            {
                "token_id": token_id,
                "name": token_data.name,
                "description": token_data.description,
                "expires_at": expires_at,
                "created_by": current_user.username,
            },
        )

        # Generate JWT token with custom expiration
        payload = {
            "sub": f"token:{token_id}",  # Prefix to distinguish from user IDs
            "name": current_user.username,
            "token_id": token_id,
            "iat": datetime.utcnow(),
            "exp": expires_at,
            "admin": current_user.is_admin,  # Preserve admin privileges
        }

        token = jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")

        # Create response object
        response = TokenResponse(
            token=token,
            token_id=token_id,
            name=token_data.name,
            expires_at=expires_at,
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
def list_tokens() -> Tuple[Dict[str, Any], int]:
    """List all tokens for the current admin user.

    Returns:
        tuple: A tuple containing:
            - Dict with list of tokens
            - HTTP status code
    """
    try:
        current_user = request.current_user

        # Get database client
        db_client = client_factory.get_database_client()

        # Retrieve tokens created by current user
        query = """
        SELECT *
        FROM api_tokens
        WHERE created_by = :username
        ORDER BY created_at DESC
        """

        tokens, _ = db_client.execute_query(query, {"username": current_user.username})

        # Convert to Pydantic models for validation and to format dates correctly
        token_list = [Token(**token) for token in tokens]

        return jsonify({"tokens": [t.model_dump() for t in token_list]}), HTTPStatus.OK

    except Exception as e:
        logger.error("Failed to list API tokens: %s", str(e))
        return (
            jsonify({"error": "Failed to list API tokens", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@token_bp.route("/api/tokens/<token_id>", methods=["GET"])
@token_required
@admin_required
def get_token(token_id: str) -> Tuple[Dict[str, Any], int]:
    """Get details for a specific token.

    Args:
        token_id: The unique ID of the token

    Returns:
        tuple: A tuple containing:
            - Dict with token details
            - HTTP status code
    """
    try:
        current_user = request.current_user

        # Get database client
        db_client = client_factory.get_database_client()

        # Retrieve token details
        query = """
        SELECT *
        FROM api_tokens
        WHERE token_id = :token_id AND created_by = :username
        """

        tokens, count = db_client.execute_query(
            query, {"token_id": token_id, "username": current_user.username}
        )

        if count == 0:
            return jsonify({"error": "Token not found"}), HTTPStatus.NOT_FOUND

        # Convert to Pydantic model
        token = Token(**tokens[0])

        return jsonify(token.model_dump()), HTTPStatus.OK

    except Exception as e:
        logger.error("Failed to get API token: %s", str(e))
        return (
            jsonify({"error": "Failed to get API token", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@token_bp.route("/api/tokens/<token_id>", methods=["DELETE"])
@token_required
@admin_required
def revoke_token(token_id: str) -> Tuple[Dict[str, Any], int]:
    """Revoke (delete) a token.

    Args:
        token_id: The unique ID of the token to revoke

    Returns:
        tuple: A tuple containing:
            - Dict with success message
            - HTTP status code
    """
    try:
        current_user = request.current_user

        # Get database client
        db_client = client_factory.get_database_client()

        # Mark token as revoked
        update_query = """
        UPDATE api_tokens
        SET revoked = TRUE, revoked_at = :revoked_at
        WHERE token_id = :token_id AND created_by = :username AND revoked = FALSE
        """

        _, count = db_client.execute_query(
            update_query,
            {
                "token_id": token_id,
                "username": current_user.username,
                "revoked_at": datetime.utcnow(),
            },
        )

        if count == 0:
            # Check if token exists but is already revoked
            check_query = """
            SELECT * FROM api_tokens
            WHERE token_id = :token_id AND created_by = :username
            """
            tokens, token_count = db_client.execute_query(
                check_query, {"token_id": token_id, "username": current_user.username}
            )

            if token_count == 0:
                return jsonify({"error": "Token not found"}), HTTPStatus.NOT_FOUND
            else:
                return jsonify({"error": "Token is already revoked"}), HTTPStatus.BAD_REQUEST

        return jsonify({"message": "Token successfully revoked"}), HTTPStatus.OK

    except Exception as e:
        logger.error("Failed to revoke API token: %s", str(e))
        return (
            jsonify({"error": "Failed to revoke API token", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )
