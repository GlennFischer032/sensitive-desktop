from datetime import datetime
from http import HTTPStatus
import logging
from typing import Any, Dict, Tuple

from flask import Blueprint, jsonify, request
from pydantic import ValidationError
import requests
from werkzeug.security import generate_password_hash

from desktop_manager.api.models.user import User
from desktop_manager.api.schemas.user import UserCreate, UserList, UserResponse
from desktop_manager.api.utils.error_handlers import handle_validation_error
from desktop_manager.clients.factory import client_factory
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
        db_client = client_factory.get_database_client()

        # Check if user exists
        query = "SELECT * FROM users WHERE username = :username"
        users, count = db_client.execute_query(query, {"username": username})

        if count == 0:
            return jsonify({"error": "User not found"}), HTTPStatus.NOT_FOUND

        users[0]

        # Remove from Guacamole
        try:
            logging.info("Removing user from Guacamole: %s", username)
            guacamole_client = client_factory.get_guacamole_client()
            token = guacamole_client.login()
            guacamole_client.delete_user(token, username)
            logging.info("Successfully removed user from Guacamole: %s", username)
        except Exception as e:
            logging.error("Failed to remove user from Guacamole: %s", str(e))
            # Continue with removal from database even if Guacamole fails

        # Remove user from database
        delete_query = "DELETE FROM users WHERE username = :username"
        db_client.execute_query(delete_query, {"username": username})
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
def create_user() -> Tuple[Dict[str, Any], int]:
    """Create a new user.

    This endpoint creates a new user in both the application database and Guacamole.

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

        try:
            user_data = UserCreate(**data)
        except ValidationError as e:
            return handle_validation_error(e)

        # Get database client
        db_client = client_factory.get_database_client()

        # Check if username or email already exists
        check_query = (
            "SELECT username, email FROM users WHERE username = :username OR email = :email"
        )
        existing_users, count = db_client.execute_query(
            check_query, {"username": user_data.username, "email": user_data.email}
        )

        if count > 0:
            # Check which field already exists
            for user in existing_users:
                if user["username"] == user_data.username:
                    return jsonify({"error": "Username already exists"}), HTTPStatus.CONFLICT
                if user["email"] == user_data.email:
                    return jsonify({"error": "Email already exists"}), HTTPStatus.CONFLICT

        # Hash password
        password_hash = generate_password_hash(user_data.password)

        # Insert into database
        insert_query = """
        INSERT INTO users (username, email, password_hash, is_admin, created_at)
        VALUES (:username, :email, :password_hash, :is_admin, :created_at)
        RETURNING id, username, email, is_admin, created_at
        """

        result, _ = db_client.execute_query(
            insert_query,
            {
                "username": user_data.username,
                "email": user_data.email,
                "password_hash": password_hash,
                "is_admin": user_data.is_admin,
                "created_at": datetime.utcnow(),
            },
        )

        new_user = result[0]
        logging.info("Created user in database: %s", user_data.username)

        # Create in Guacamole
        try:
            guacamole_client = client_factory.get_guacamole_client()
            token = guacamole_client.login()

            # Create user in Guacamole
            guacamole_client.create_user_if_not_exists(
                token, user_data.username, user_data.password
            )
            logging.info("Created user in Guacamole: %s", user_data.username)

            # Add user to appropriate groups
            if user_data.is_admin:
                guacamole_client.ensure_group(token, "admins")
                guacamole_client.add_user_to_group(token, user_data.username, "admins")
                logging.info("Added user to admins group: %s", user_data.username)

            guacamole_client.ensure_group(token, "all_users")
            guacamole_client.add_user_to_group(token, user_data.username, "all_users")
            logging.info("Added user to all_users group: %s", user_data.username)
        except Exception as e:
            logging.error("Error creating user in Guacamole: %s", str(e))
            # Continue even if Guacamole fails

        # Format response
        user_response = UserResponse(
            id=new_user["id"],
            username=new_user["username"],
            email=new_user["email"],
            is_admin=new_user["is_admin"],
            created_at=new_user["created_at"],
        )

        return jsonify(user_response.dict()), HTTPStatus.CREATED

    except Exception as e:
        logging.error("Error creating user: %s", str(e))
        return (
            jsonify({"error": "Failed to create user", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@users_bp.route("/list", methods=["GET"])
@token_required
@admin_required
def list_users() -> Tuple[Dict[str, Any], int]:
    """List all users.

    This endpoint lists all users in the system.

    Returns:
        tuple: A tuple containing:
            - Dict with list of users
            - HTTP status code
    """
    try:
        # Get database client
        db_client = client_factory.get_database_client()

        # Query all users
        query = """
        SELECT id, username, email, is_admin, created_at, last_login
        FROM users
        ORDER BY username
        """
        users, _ = db_client.execute_query(query)

        # Format response
        user_list = UserList(
            users=[
                UserResponse(
                    id=user["id"],
                    username=user["username"],
                    email=user["email"],
                    is_admin=user["is_admin"],
                    created_at=user["created_at"],
                    last_login=user["last_login"],
                )
                for user in users
            ]
        )

        return jsonify(user_list.dict()), HTTPStatus.OK

    except Exception as e:
        logging.error("Error listing users: %s", str(e))
        return (
            jsonify({"error": "Failed to list users", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@users_bp.route("/check", methods=["GET"])
def check_user() -> Tuple[Dict[str, Any], int]:
    """Check if a user exists.

    This endpoint checks if a user with the given username exists in the system.

    Returns:
        tuple: A tuple containing:
            - Dict with existence flag
            - HTTP status code
    """
    try:
        username = request.args.get("username")
        if not username:
            return (
                jsonify({"error": "Missing username parameter"}),
                HTTPStatus.BAD_REQUEST,
            )

        # Get database client
        db_client = client_factory.get_database_client()

        # Check if user exists
        query = "SELECT id FROM users WHERE username = :username"
        _, count = db_client.execute_query(query, {"username": username})

        exists = count > 0

        return jsonify({"exists": exists}), HTTPStatus.OK

    except Exception as e:
        logging.error("Error checking user: %s", str(e))
        return (
            jsonify({"error": "Failed to check user", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )
