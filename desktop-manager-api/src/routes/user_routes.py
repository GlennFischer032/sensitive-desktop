from http import HTTPStatus
import logging
from typing import Any

from clients.factory import client_factory
from core.auth import admin_required, token_required
from database.core.session import get_db_session
from database.repositories.user import UserRepository
from flask import Blueprint, jsonify, request
from schemas.user import UserList, UserResponse


users_bp = Blueprint("users_bp", __name__)


@users_bp.route("/removeuser", methods=["POST"])
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
        logging.info("Request to remove user: %s", username)

        # Get the current authenticated user
        current_user = request.current_user
        if current_user.username == username:
            return (
                jsonify({"error": "You cannot remove your own account"}),
                HTTPStatus.BAD_REQUEST,
            )

        # Get database client
        with get_db_session() as session:
            user_repo = UserRepository(session)
            user = user_repo.get_by_username(username)
            if not user:
                return jsonify({"error": "User not found"}), HTTPStatus.NOT_FOUND

            try:
                logging.info("Removing user from Guacamole: %s", username)
                guacamole_client = client_factory.get_guacamole_client()
                token = guacamole_client.login()
                guacamole_client.delete_user(token, username)
                logging.info("Successfully removed user from Guacamole: %s", username)
            except Exception as e:
                logging.error("Failed to remove user from Guacamole: %s", str(e))

            user_repo.delete_user(user.id)
            logging.info("Successfully removed user from database: %s", username)

        return jsonify({"message": "User removed successfully"}), HTTPStatus.OK

    except Exception as e:
        logging.error("Error removing user: %s", str(e))
        return (
            jsonify({"error": "Failed to remove user", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@users_bp.route("/createuser", methods=["POST"])
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
        if not data:
            return jsonify({"error": "Missing request data"}), HTTPStatus.BAD_REQUEST

        # Check for required fields
        username = data.get("username")
        sub = data.get("sub")
        is_admin = data.get("is_admin", False)

        if not username or not sub:
            return jsonify({"error": "Username and sub are required"}), HTTPStatus.BAD_REQUEST

        if len(username) < 3:
            return jsonify({"error": "Username must be at least 3 characters long"}), HTTPStatus.BAD_REQUEST

        with get_db_session() as session:
            user_repo = UserRepository(session)
            existing_users = user_repo.get_by_username(username) or user_repo.get_by_sub(sub)

            if existing_users:
                # Check which field already exists
                if existing_users.username == username:
                    return jsonify({"error": "Username already exists"}), HTTPStatus.CONFLICT
                if existing_users.sub == sub:
                    return jsonify({"error": "User with this OIDC subject already exists"}), HTTPStatus.CONFLICT

            # Create minimal user with just username and sub
            # Other fields will be populated during the first OIDC login
            user = user_repo.create_user({"username": username, "sub": sub, "is_admin": is_admin})

            logging.info("Created user in database: %s with sub: %s", username, sub)

            # Create in Guacamole
            try:
                guacamole_client = client_factory.get_guacamole_client()
                token = guacamole_client.login()

                # Create user in Guacamole with empty password for JSON auth
                guacamole_client.create_user_if_not_exists(
                    token=token,
                    username=username,
                    password="",  # Empty password for JSON auth
                    attributes={
                        "guac_full_name": f"{username} ({sub})",
                        "guac_organization": "Default",
                    },
                )

                # Add user to appropriate groups
                if is_admin:
                    guacamole_client.ensure_group(token, "admins")
                    guacamole_client.add_user_to_group(token, username, "admins")
                    logging.info("Added user to admins group: %s", username)

                guacamole_client.ensure_group(token, "all_users")
                guacamole_client.add_user_to_group(token, username, "all_users")
                logging.info("Added user to all_users group: %s", username)
            except Exception as e:
                logging.error("Error creating user in Guacamole: %s", str(e))
                # Continue even if Guacamole fails

            # Format response
            user_response = {
                "id": user.id,
                "username": user.username,
                "is_admin": user.is_admin,
                "created_at": user.created_at,
                "message": "User created successfully. User details will be filled from OIDC during first login.",
            }

            return jsonify(user_response), HTTPStatus.CREATED

    except Exception as e:
        logging.error("Error creating user: %s", str(e))
        return (
            jsonify({"error": "Failed to create user", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@users_bp.route("/list", methods=["GET"])
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
        with get_db_session() as session:
            user_repo = UserRepository(session)
            users = user_repo.get_all_users()

            # Format response
            user_list = UserList(
                users=[
                    UserResponse(
                        id=user.id,
                        username=user.username,
                        email=user.email,
                        is_admin=user.is_admin,
                        organization=user.organization,
                        created_at=user.created_at,
                        last_login=user.last_login,
                        sub=user.sub,
                        given_name=user.given_name,
                        family_name=user.family_name,
                        name=user.name,
                        locale=user.locale,
                        email_verified=user.email_verified,
                    )
                    for user in users
                ]
            )

            return jsonify(user_list.model_dump()), HTTPStatus.OK

    except Exception as e:
        logging.error("Error listing users: %s", str(e))
        return (
            jsonify({"error": "Failed to list users", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@users_bp.route("/<username>", methods=["GET"])
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
        with get_db_session() as session:
            user_repo = UserRepository(session)
            user = user_repo.get_by_username(username)

            if not user:
                return jsonify({"error": "User not found"}), HTTPStatus.NOT_FOUND

            associations = user.social_auth
            # Format user information
            user_info = {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "organization": user.organization,
                "is_admin": user.is_admin,
                "created_at": user.created_at,
                "sub": user.sub,
                "given_name": user.given_name,
                "family_name": user.family_name,
                "name": user.name,
                "locale": user.locale,
                "email_verified": user.email_verified,
                "last_login": user.last_login,
                "auth_providers": [
                    {
                        "provider": assoc.provider,
                        "provider_user_id": assoc.provider_user_id,
                        "provider_name": assoc.provider_name,
                        "created_at": assoc.created_at,
                        "last_used": assoc.last_used,
                    }
                    for assoc in associations
                ],
            }

            return jsonify({"user": user_info}), HTTPStatus.OK

    except Exception as e:
        logging.error("Error getting user: %s", str(e))
        return (
            jsonify({"error": "Failed to get user information", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@users_bp.route("/verify", methods=["GET"])  # TODO: Remove this endpoint
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
        if not sub:
            return (
                jsonify({"error": "Missing sub parameter"}),
                HTTPStatus.BAD_REQUEST,
            )

        with get_db_session() as session:
            user_repo = UserRepository(session)
            user = user_repo.get_by_sub(sub)

            if not user:
                return (
                    jsonify({"exists": False, "message": "User not found"}),
                    HTTPStatus.NOT_FOUND,
                )

            return (
                jsonify({"exists": True, "user_id": user.id, "username": user.username}),
                HTTPStatus.OK,
            )

    except Exception as e:
        logging.error("Error verifying user by sub: %s", str(e))
        return (
            jsonify({"error": "Failed to verify user", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )
