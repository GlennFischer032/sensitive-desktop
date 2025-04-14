from http import HTTPStatus
import logging
from typing import Any

from core.auth import admin_required, token_required
from database.core.session import with_db_session
from flask import Blueprint, jsonify, request
from services.connections import APIError
from services.user import UserService


users_bp = Blueprint("users_bp", __name__)


@users_bp.route("/removeuser", methods=["POST"])
@with_db_session
@token_required
@admin_required
def remove_user() -> tuple[dict[str, Any], int]:
    """Remove a user from the system.

    This endpoint removes a user from both the application database and Guacamole.
    It ensures proper cleanup of user resources.

    Returns:
        tuple: A tuple containing:
            - Dict with success/error message
            - HTTP status code
    """
    try:
        data = request.get_json()
        if not data or "username" not in data:
            return (
                jsonify({"error": "Missing username in request data"}),
                HTTPStatus.BAD_REQUEST,
            )

        username = data["username"]

        # Get the current authenticated user
        current_user = request.current_user

        # Create UserService instance and remove user
        user_service = UserService()
        response_data = user_service.remove_user(username, current_user, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in remove_user: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logging.error("Error removing user: %s", str(e))
        return (
            jsonify({"error": "Failed to remove user", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@users_bp.route("/createuser", methods=["POST"])
@with_db_session
@token_required
@admin_required
def create_user() -> tuple[dict[str, Any], int]:
    """Create a new user.

    This endpoint creates a new user in both the application database and Guacamole.
    Only username and OIDC subject identifier are required, other user details
    will be filled from OIDC during the user's first login.

    Returns:
        tuple: A tuple containing:
            - Dict with success/error message
            - HTTP status code
    """
    try:
        # Parse and validate request data
        data = request.get_json()

        # Create UserService instance and create user
        user_service = UserService()
        response_data = user_service.create_user(data, request.db_session)

        return jsonify(response_data), HTTPStatus.CREATED

    except APIError as e:
        logging.error("API error in create_user: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logging.error("Error creating user: %s", str(e))
        return (
            jsonify({"error": "Failed to create user", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@users_bp.route("/list", methods=["GET"])
@with_db_session
@token_required
@admin_required
def list_users() -> tuple[dict[str, Any], int]:
    """List all users.

    This endpoint lists all users in the system.

    Returns:
        tuple: A tuple containing:
            - Dict with list of users
            - HTTP status code
    """
    try:
        # Create UserService instance and list users
        user_service = UserService()
        response_data = user_service.list_users(request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in list_users: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logging.error("Error listing users: %s", str(e))
        return (
            jsonify({"error": "Failed to list users", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@users_bp.route("/<username>", methods=["GET"])
@with_db_session
@token_required
@admin_required
def get_user(username: str) -> tuple[dict[str, Any], int]:
    """Get detailed user information.

    This endpoint returns detailed information about a specific user,
    including their OIDC information.

    Args:
        username: The username of the user to get information for

    Returns:
        tuple: A tuple containing:
            - Dict with user information
            - HTTP status code
    """
    try:
        # Create UserService instance and get user
        user_service = UserService()
        response_data = user_service.get_user(username, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in get_user: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logging.error("Error getting user: %s", str(e))
        return (
            jsonify({"error": "Failed to get user information", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@users_bp.route("/verify", methods=["GET"])  # TODO: Remove this endpoint
@with_db_session
def verify_user_by_sub() -> tuple[dict[str, Any], int]:
    """Verify if a user with the given sub exists.

    This endpoint is used by the debug login feature to verify if a user with
    the provided sub exists in the database.

    Returns:
        tuple: A tuple containing:
            - Dict with verification result
            - HTTP status code
    """
    try:
        sub = request.args.get("sub")

        # Create UserService instance and verify user by sub
        user_service = UserService()
        try:
            response_data = user_service.verify_user_by_sub(sub, request.db_session)
            return jsonify(response_data), HTTPStatus.OK
        except APIError as e:
            if e.status_code == HTTPStatus.NOT_FOUND:
                return (
                    jsonify({"exists": False, "message": "User not found"}),
                    HTTPStatus.NOT_FOUND,
                )
            raise

    except APIError as e:
        logging.error("API error in verify_user_by_sub: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logging.error("Error verifying user by sub: %s", str(e))
        return (
            jsonify({"error": "Failed to verify user", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )
