from datetime import datetime
from http import HTTPStatus
import logging
from typing import Any, Dict, Tuple

from flask import Blueprint, jsonify, request
from pydantic import ValidationError
import requests
from werkzeug.security import generate_password_hash

from desktop_manager.api.models.base import get_db
from desktop_manager.api.models.user import User
from desktop_manager.api.schemas.user import UserCreate, UserList, UserResponse
from desktop_manager.api.utils.error_handlers import handle_validation_error
from desktop_manager.clients.guacamole import (
    add_user_to_group,
    create_guacamole_user,
    delete_guacamole_user,
    ensure_all_users_group,
    guacamole_login,
    remove_user_from_group,
)
from desktop_manager.config.settings import get_settings
from desktop_manager.core.auth import admin_required, token_required


users_bp = Blueprint("users_bp", __name__)


@users_bp.route("/removeuser", methods=["POST"])
@token_required
@admin_required
def remove_user() -> Tuple[Dict[str, Any], int]:
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
        username = data.get("username")

        if not username:
            return (
                jsonify(
                    {
                        "error": "Validation Error",
                        "details": {"username": ["This field is required"]},
                    }
                ),
                HTTPStatus.BAD_REQUEST,
            )

        settings = get_settings()
        if username == settings.GUACAMOLE_USERNAME:
            return (
                jsonify({"error": "Cannot remove service user"}),
                HTTPStatus.FORBIDDEN,
            )

        # Get database session
        db_session = next(get_db())
        try:
            # Check if user exists in database
            user = db_session.query(User).filter(User.username == username).first()
            if not user:
                return (
                    jsonify(
                        {
                            "error": "Not Found",
                            "details": {"username": ["User not found"]},
                        }
                    ),
                    HTTPStatus.NOT_FOUND,
                )

            # Delete from Guacamole first
            token = guacamole_login()
            try:
                delete_guacamole_user(token, username)
                logging.info("User '%s' removed from Guacamole", username)
            except Exception as e:
                logging.error("Failed to remove user from Guacamole: %s", str(e))
                raise

            # Then delete from database
            db_session.delete(user)
            db_session.commit()
            logging.info("User '%s' removed from database", username)

            return (
                jsonify({"message": f"User '{username}' removed successfully"}),
                HTTPStatus.OK,
            )

        except Exception as e:
            db_session.rollback()
            logging.error("Database error while removing user: %s", str(e))
            raise
        finally:
            db_session.close()

    except Exception as e:
        logging.error("Error removing user: %s", str(e))
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@users_bp.route("/createuser", methods=["POST"])
@token_required
@admin_required
def create_user() -> Tuple[Dict[str, Any], int]:
    """Create a new user in the system.

    This endpoint creates a new user in both the application database and Guacamole.
    It validates the input data and ensures proper setup of user permissions and groups.

    Returns:
        tuple: A tuple containing:
            - Dict with success/error message
            - HTTP status code
    """
    try:
        # Validate input using Pydantic
        try:
            user_data = UserCreate(**request.get_json())
        except ValidationError as e:
            return handle_validation_error(e)

        token = guacamole_login()

        # Check if user already exists
        db_session = next(get_db())
        try:
            existing_user = (
                db_session.query(User).filter(User.username == user_data.username).first()
            )
            if existing_user:
                return (
                    jsonify(
                        {
                            "error": "Validation Error",
                            "details": {"username": ["Username already exists"]},
                        }
                    ),
                    HTTPStatus.BAD_REQUEST,
                )
        finally:
            db_session.close()

        # Create user in Guacamole
        try:
            guacamole_password = user_data.password if user_data.password else ""

            attributes = {
                "disabled": "true" if not user_data.password else "",
                "expired": "",
                "access-window-start": "",
                "access-window-end": "",
                "valid-from": "",
                "valid-until": "",
                "timezone": None,
                "guac-full-name": user_data.username,
                "guac-email-address": user_data.email,
                "guac-organization": user_data.organization or "",
            }

            create_guacamole_user(token, user_data.username, guacamole_password, attributes)
            ensure_all_users_group(token)
            add_user_to_group(token, user_data.username, "all_users")
            logging.info("Created user %s in Guacamole with attributes", user_data.username)
        except Exception as e:
            logging.error("Failed to create user in Guacamole: %s", str(e))
            raise

        # Create user in database
        db_session = next(get_db())
        try:
            user = User(
                username=user_data.username,
                email=user_data.email,
                organization=user_data.organization,
                password_hash=(
                    generate_password_hash(user_data.password) if user_data.password else None
                ),
                is_admin=user_data.is_admin,
                sub=user_data.sub,
            )
            db_session.add(user)
            db_session.commit()

            # Create response using Pydantic model
            response_data = UserResponse(
                id=user.id,
                username=user.username,
                email=user.email,
                organization=user.organization,
                is_admin=user.is_admin,
                created_at=user.created_at,
            )

            return (
                jsonify(
                    {
                        "message": f"User '{user_data.username}' created successfully",
                        "user": response_data.model_dump(),
                    }
                ),
                HTTPStatus.CREATED,
            )

        except Exception:
            db_session.rollback()
            # Cleanup Guacamole user if database fails
            try:
                delete_guacamole_user(token, user_data.username)
                logging.info(
                    "Cleaned up Guacamole user %s after database error",
                    user_data.username,
                )
            except Exception as cleanup_error:
                logging.error("Failed to cleanup Guacamole user: %s", cleanup_error)
            raise
        finally:
            db_session.close()

    except Exception as e:
        logging.error("Error creating user: %s", str(e))
        if isinstance(e, ValidationError):
            return handle_validation_error(e)
        return (
            jsonify({"error": "Internal Server Error", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@users_bp.route("/list", methods=["GET"])
@token_required
@admin_required
def list_users() -> Tuple[Dict[str, Any], int]:
    """List all users in the system.

    This endpoint retrieves all users from both the application database
    and Guacamole, combining the information into a comprehensive response.

    Returns:
        tuple: A tuple containing:
            - Dict with list of users
            - HTTP status code
    """
    try:
        settings = get_settings()
        token = guacamole_login()

        # Get users from Guacamole
        users_url = f"{settings.GUACAMOLE_URL}/api/session/data/postgresql/users?token={token}"
        response = requests.get(users_url, timeout=10)
        response.raise_for_status()
        guacamole_users = response.json()

        # Get users from database
        db_session = next(get_db())
        try:
            users_list = []
            for user in db_session.query(User).all():
                # Skip the Guacamole service user
                if user.username == settings.GUACAMOLE_USERNAME:
                    continue

                # Get Guacamole info if available
                guac_info = guacamole_users.get(user.username, {})
                last_active = None
                if guac_info.get("lastActive"):
                    last_active = datetime.utcfromtimestamp(guac_info["lastActive"] / 1000)

                user_response = UserResponse(
                    id=user.id,
                    username=user.username,
                    email=user.email,
                    organization=user.organization,
                    is_admin=user.is_admin,
                    created_at=user.created_at,
                    last_active=last_active,
                )
                users_list.append(user_response)

            response_data = UserList(users=users_list)
            return jsonify(response_data.model_dump()), HTTPStatus.OK

        finally:
            db_session.close()

    except Exception as e:
        logging.error("Error listing users: %s", str(e))
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@users_bp.route("/check", methods=["GET"])
def check_user() -> Tuple[Dict[str, Any], int]:
    """Check if a user exists by email.

    This endpoint checks if a user exists in the database and returns their basic info.
    It does not require authentication as it's used during the OIDC login process.

    Returns:
        tuple: A tuple containing:
            - Dict with user info or error message
            - HTTP status code
    """
    try:
        email = request.args.get("email")
        if not email:
            return (
                jsonify(
                    {
                        "error": "Validation Error",
                        "details": {"email": ["This field is required"]},
                    }
                ),
                HTTPStatus.BAD_REQUEST,
            )

        db_session = next(get_db())
        try:
            user = db_session.query(User).filter(User.email == email).first()
            if not user:
                return jsonify({"error": "User not found"}), HTTPStatus.NOT_FOUND

            return (
                jsonify(
                    {
                        "username": user.username,
                        "email": user.email,
                        "is_admin": user.is_admin,
                        "organization": user.organization,
                    }
                ),
                HTTPStatus.OK,
            )

        finally:
            db_session.close()

    except Exception as e:
        logging.error("Error checking user: %s", str(e))
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR
