from datetime import datetime
from http import HTTPStatus
import logging
from typing import Any, Dict, Tuple

from flask import Blueprint, jsonify, request

from desktop_manager.api.schemas.user import UserList, UserResponse
from desktop_manager.clients.factory import client_factory
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
            return jsonify(
                {"error": "Username must be at least 3 characters long"}
            ), HTTPStatus.BAD_REQUEST

        # Get database client
        db_client = client_factory.get_database_client()

        # Check if username or sub already exists
        check_query = """
        SELECT username, sub FROM users
        WHERE username = :username OR sub = :sub
        """
        existing_users, count = db_client.execute_query(
            check_query, {"username": username, "sub": sub}
        )

        if count > 0:
            # Check which field already exists
            for user in existing_users:
                if user["username"] == username:
                    return jsonify({"error": "Username already exists"}), HTTPStatus.CONFLICT
                if user["sub"] == sub:
                    return jsonify(
                        {"error": "User with this OIDC subject already exists"}
                    ), HTTPStatus.CONFLICT

        # Create minimal user with just username and sub
        # Other fields will be populated during the first OIDC login
        insert_query = """
        INSERT INTO users (username, sub, is_admin, created_at)
        VALUES (:username, :sub, :is_admin, :created_at)
        RETURNING id, username, is_admin, created_at
        """

        query_params = {
            "username": username,
            "sub": sub,
            "is_admin": is_admin,
            "created_at": datetime.utcnow(),
        }

        result, _ = db_client.execute_query(insert_query, query_params)

        new_user = result[0]
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
            logging.info("Created user in Guacamole with JSON auth: %s", username)

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
            "id": new_user["id"],
            "username": new_user["username"],
            "is_admin": new_user["is_admin"],
            "created_at": new_user["created_at"],
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
        SELECT id, username, email, is_admin, created_at, last_login,
               organization, sub, given_name, family_name, name, locale, email_verified
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
                    organization=user["organization"],
                    created_at=user["created_at"],
                    last_login=user["last_login"],
                    sub=user["sub"],
                    given_name=user["given_name"],
                    family_name=user["family_name"],
                    name=user["name"],
                    locale=user["locale"],
                    email_verified=user["email_verified"],
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


@users_bp.route("/<username>", methods=["GET"])
@token_required
@admin_required
def get_user(username: str) -> Tuple[Dict[str, Any], int]:
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
        # Get database client
        db_client = client_factory.get_database_client()

        # Get user information
        query = """
        SELECT
            u.id, u.username, u.email, u.organization, u.is_admin,
            u.created_at, u.sub, u.given_name, u.family_name, u.name,
            u.locale, u.email_verified, u.last_login
        FROM
            users u
        WHERE
            u.username = :username
        """
        users, count = db_client.execute_query(query, {"username": username})

        if count == 0:
            return jsonify({"error": "User not found"}), HTTPStatus.NOT_FOUND

        user = users[0]

        # Get social auth associations
        query = """
        SELECT
            provider, provider_user_id, provider_name, created_at, last_used
        FROM
            social_auth_association
        WHERE
            user_id = :user_id
        """
        associations, _ = db_client.execute_query(query, {"user_id": user["id"]})

        # Format user information
        user_info = {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "organization": user["organization"],
            "is_admin": user["is_admin"],
            "created_at": user["created_at"],
            "sub": user["sub"],
            "given_name": user["given_name"],
            "family_name": user["family_name"],
            "name": user["name"],
            "locale": user["locale"],
            "email_verified": user["email_verified"],
            "last_login": user["last_login"],
            "auth_providers": [
                {
                    "provider": assoc["provider"],
                    "provider_user_id": assoc["provider_user_id"],
                    "provider_name": assoc["provider_name"],
                    "created_at": assoc["created_at"],
                    "last_used": assoc["last_used"],
                }
                for assoc in associations
            ],
        }

        # Get last activity from Guacamole if available
        try:
            guacamole_client = client_factory.get_guacamole_client()
            token = guacamole_client.login()
            guac_user = guacamole_client.get_user(token, username)
            if guac_user:
                user_info["last_active"] = guac_user.get("lastActive")
        except Exception as e:
            logging.warning("Error fetching Guacamole user data: %s", str(e))

        return jsonify({"user": user_info}), HTTPStatus.OK

    except Exception as e:
        logging.error("Error getting user: %s", str(e))
        return (
            jsonify({"error": "Failed to get user information", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@users_bp.route("/update/<username>", methods=["POST"])
@token_required
@admin_required
def update_user(username: str) -> Tuple[Dict[str, Any], int]:
    """Update user information.

    This endpoint updates specific fields for a user, such as organization or admin status.

    Args:
        username: The username of the user to update

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

        # Get database client
        db_client = client_factory.get_database_client()

        # Check if user exists
        query = "SELECT id FROM users WHERE username = :username"
        users, count = db_client.execute_query(query, {"username": username})

        if count == 0:
            return jsonify({"error": "User not found"}), HTTPStatus.NOT_FOUND

        user_id = users[0]["id"]

        # Initialize update fields
        update_fields = []
        params = {"user_id": user_id}

        # Check which fields to update
        if "organization" in data:
            update_fields.append("organization = :organization")
            params["organization"] = data["organization"]

        if "is_admin" in data:
            update_fields.append("is_admin = :is_admin")
            params["is_admin"] = data["is_admin"]

        if "locale" in data:
            update_fields.append("locale = :locale")
            params["locale"] = data["locale"]

        if not update_fields:
            return jsonify({"error": "No fields to update provided"}), HTTPStatus.BAD_REQUEST

        # Build and execute update query
        update_query = (
            """
        UPDATE users SET
        """
            + ", ".join(update_fields)
            + """,
            updated_at = :updated_at
        WHERE id = :user_id
        """
        )

        params["updated_at"] = datetime.utcnow()

        db_client.execute_query(update_query, params)

        # Update Guacamole if possible
        if "organization" in data:
            try:
                guacamole_client = client_factory.get_guacamole_client()
                token = guacamole_client.login()
                guac_user = guacamole_client.get_user(token, username)

                if guac_user:
                    # Update organization attribute in Guacamole
                    attributes = guac_user.get("attributes", {})
                    attributes["guac_organization"] = data["organization"]
                    guacamole_client.update_user(token, username, attributes=attributes)
                    logging.info("Updated organization for user %s in Guacamole", username)
            except Exception as e:
                logging.warning("Failed to update organization in Guacamole: %s", str(e))

        return jsonify({"message": "User updated successfully"}), HTTPStatus.OK

    except Exception as e:
        logging.error("Error updating user: %s", str(e))
        return (
            jsonify({"error": "Failed to update user", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@users_bp.route("/verify", methods=["GET"])
def verify_user_by_sub() -> Tuple[Dict[str, Any], int]:
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

        # Get database client
        db_client = client_factory.get_database_client()

        # Check if user exists with the provided sub
        query = "SELECT id, username FROM users WHERE sub = :sub"
        users, count = db_client.execute_query(query, {"sub": sub})

        if count == 0:
            return (
                jsonify({"exists": False, "message": "User not found"}),
                HTTPStatus.NOT_FOUND,
            )

        user = users[0]
        return (
            jsonify({"exists": True, "user_id": user["id"], "username": user["username"]}),
            HTTPStatus.OK,
        )

    except Exception as e:
        logging.error("Error verifying user by sub: %s", str(e))
        return (
            jsonify({"error": "Failed to verify user", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )
