from datetime import datetime

from flask import Blueprint, current_app, jsonify, request

from desktop_manager.clients.factory import client_factory
from desktop_manager.core.auth import admin_required, token_required


auth_bp = Blueprint("auth_bp", __name__)


@auth_bp.route("/login", methods=["POST"])
def login():
    """User login endpoint.
    ---
    tags:
      - Authentication
    requestBody:
      required: false
      content:
        application/json:
          schema:
            type: object
    responses:
      400:
        description: Username/password authentication has been disabled
      500:
        description: Internal server error.
    """
    return jsonify(
        {
            "error": "Username/password authentication has been disabled",
            "message": "Please use OIDC authentication instead",
            "oidc_login_url": "/api/auth/oidc/login",
        }
    ), 400


@auth_bp.route("/register", methods=["POST"])
@token_required
@admin_required
def register():
    """Register a new user for OIDC authentication.

    This endpoint allows administrators to pre-register users for OIDC authentication.
    It creates a minimal user record that will be populated with details from the
    OIDC provider when the user first logs in.

    ---
    tags:
      - Authentication
    security:
      - BearerAuth: []
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              username:
                type: string
                description: The username of the new user
              email:
                type: string
                description: The email of the new user
              sub:
                type: string
                description: OIDC subject identifier
              is_admin:
                type: boolean
                description: Whether the new user is an admin
              organization:
                type: string
                description: The user's organization
            required:
              - username
              - email
              - sub
    responses:
      201:
        description: User created successfully
      400:
        description: Missing request data or invalid input
      401:
        description: Unauthorized
      403:
        description: Forbidden - Only admins can register new users
      409:
        description: Username or email already exists
      500:
        description: Internal server error
    """
    # Get request data
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing request data"}), 400

    # Extract user details
    username = data.get("username")
    email = data.get("email")
    sub = data.get("sub")
    is_admin = data.get("is_admin", False)
    organization = data.get("organization")

    if not username or not email or not sub:
        return jsonify({"error": "Missing required fields: username, email, and sub are required"}), 400

    try:
        # Get database client
        db_client = client_factory.get_database_client()

        # Check if username, email, or sub already exists
        check_query = """
        SELECT username, email, sub FROM users
        WHERE username = :username OR email = :email OR sub = :sub
        """
        existing_users, count = db_client.execute_query(check_query, {"username": username, "email": email, "sub": sub})

        if count > 0:
            # Check which field already exists
            for user in existing_users:
                if user["username"] == username:
                    return jsonify({"error": "Username already exists"}), 409
                if user["email"] == email:
                    return jsonify({"error": "Email already exists"}), 409
                if user["sub"] == sub:
                    return jsonify({"error": "User with this OIDC subject already exists"}), 409

        # Create new user with OIDC sub
        insert_query = """
        INSERT INTO users (username, email, sub, is_admin, created_at, organization)
        VALUES (:username, :email, :sub, :is_admin, :created_at, :organization)
        """

        db_client.execute_query(
            insert_query,
            {
                "username": username,
                "email": email,
                "sub": sub,
                "is_admin": is_admin,
                "created_at": datetime.utcnow(),
                "organization": organization,
            },
        )

        # Create user in Guacamole
        try:
            guacamole_client = client_factory.get_guacamole_client()
            token = guacamole_client.login()

            # Create user in Guacamole with empty password for JSON auth
            guacamole_client.create_user_if_not_exists(
                token=token,
                username=username,
                password="",  # Empty password for JSON auth
                attributes={
                    "guac_full_name": f"{email} ({sub})",
                    "guac_organization": organization or "Default",
                },
            )

            # Add to appropriate groups
            if is_admin:
                guacamole_client.ensure_group(token, "admins")
                guacamole_client.add_user_to_group(token, username, "admins")

            guacamole_client.ensure_group(token, "all_users")
            guacamole_client.add_user_to_group(token, username, "all_users")
        except Exception as e:
            # Log but continue - Guacamole integration is optional
            current_app.logger.warning("Failed to create user in Guacamole: %s", str(e))

        return jsonify({"message": "User created successfully"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500
