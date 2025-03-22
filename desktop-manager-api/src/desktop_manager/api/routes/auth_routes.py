from datetime import datetime, timedelta

from flask import Blueprint, current_app, jsonify, request
import jwt
from werkzeug.security import check_password_hash, generate_password_hash

from desktop_manager.api.models.user import User
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
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              username:
                type: string
                description: The username of the user
              password:
                type: string
                description: The password of the user
            required:
              - username
              - password
    responses:
      200:
        description: Login successful
        content:
          application/json:
            schema:
              type: object
              properties:
                token:
                  type: string
                  description: JWT token for authentication
      400:
        description: Missing username or password
      401:
        description: Invalid credentials
      500:
        description: Internal server error.
    """
    # Get request data
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing request data"}), 400

    # Extract username and password
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    try:
        # Get database client
        db_client = client_factory.get_database_client()

        # Query user by username
        query = "SELECT * FROM users WHERE username = :username"
        users, count = db_client.execute_query(query, {"username": username})

        if count == 0:
            return jsonify({"error": "Invalid credentials"}), 401

        user = users[0]

        # Check password
        if not check_password_hash(user["password_hash"], password):
            return jsonify({"error": "Invalid credentials"}), 401

        # Create token
        # Get expiration time from config
        exp_time = datetime.utcnow() + timedelta(hours=2)
        payload = {
            "sub": user["id"],
            "name": user["username"],
            "iat": datetime.utcnow(),
            "exp": exp_time,
            "admin": user["is_admin"],
        }
        token = jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")

        # Update last login
        update_query = "UPDATE users SET last_login = :now WHERE id = :user_id"
        db_client.execute_query(update_query, {"now": datetime.utcnow(), "user_id": user["id"]})

        return jsonify({"token": token}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@auth_bp.route("/register", methods=["POST"])
@token_required
@admin_required
def register():
    """Register a new user.
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
              password:
                type: string
                description: The password of the new user
              email:
                type: string
                description: The email of the new user
              is_admin:
                type: boolean
                description: Whether the new user is an admin
            required:
              - username
              - password
              - email
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
        description: Internal server error.
    """
    # Get request data
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing request data"}), 400

    # Extract user details
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")
    is_admin = data.get("is_admin", False)

    if not username or not password or not email:
        return jsonify({"error": "Missing required fields"}), 400

    try:
        # Get database client
        db_client = client_factory.get_database_client()

        # Check if username or email already exists
        check_query = (
            "SELECT username, email FROM users WHERE username = :username OR email = :email"
        )
        existing_users, count = db_client.execute_query(
            check_query, {"username": username, "email": email}
        )

        if count > 0:
            # Check which field already exists
            for user in existing_users:
                if user["username"] == username:
                    return jsonify({"error": "Username already exists"}), 409
                if user["email"] == email:
                    return jsonify({"error": "Email already exists"}), 409

        # Create new user
        insert_query = """
        INSERT INTO users (username, email, password_hash, is_admin, created_at)
        VALUES (:username, :email, :password_hash, :is_admin, :created_at)
        """

        db_client.execute_query(
            insert_query,
            {
                "username": username,
                "email": email,
                "password_hash": generate_password_hash(password),
                "is_admin": is_admin,
                "created_at": datetime.utcnow(),
            },
        )

        # Create user in Guacamole if possible
        try:
            guacamole_client = client_factory.get_guacamole_client()
            token = guacamole_client.login()
            guacamole_client.create_user_if_not_exists(token, username, password)

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
