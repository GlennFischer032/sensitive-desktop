from datetime import datetime, timedelta

from flask import Blueprint, current_app, jsonify, request
import jwt
from werkzeug.security import check_password_hash, generate_password_hash

from desktop_manager.api.models.base import get_db
from desktop_manager.api.models.user import User
from desktop_manager.clients.guacamole import (
    add_user_to_group,
    create_guacamole_user,
    delete_guacamole_user,
    ensure_admins_group,
    ensure_all_users_group,
    guacamole_login,
)
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
    responses:
      200:
        description: User logged in successfully
        content:
          application/json:
            schema:
              type: object
              properties:
                token:
                  type: string
                  description: The JWT token
      401:
        description: Invalid credentials
        content:
          application/json:
            schema:
              type: object
              properties:
                message:
                  type: string
                  description: The error message.
    """
    if not request.is_json:
        return jsonify({"message": "Missing JSON in request"}), 400

    data = request.get_json()
    if not data:
        return jsonify({"message": "Missing JSON data"}), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    db_session = next(get_db())
    user = db_session.query(User).filter(User.username == username).first()

    if user and check_password_hash(user.password_hash, password):
        token_data = {
            "user_id": user.id,
            "username": user.username,
            "is_admin": user.is_admin,
            "exp": datetime.utcnow() + timedelta(hours=1),
        }
        token = jwt.encode(token_data, current_app.config["SECRET_KEY"], algorithm="HS256")
        return jsonify({"token": token, "is_admin": user.is_admin, "username": user.username})

    return jsonify({"message": "Invalid credentials"}), 401


# routes/auth_routes.py


@auth_bp.route("/register", methods=["POST"])
@token_required
@admin_required
def register():
    """User registration endpoint.
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
              email:
                type: string
                description: The email of the user
              organization:
                type: string
                description: The organization of the user
              is_admin:
                type: boolean
                description: Whether the user is an admin or not
    responses:
      201:
        description: User created successfully
        content:
          application/json:
            schema:
              type: object
              properties:
                message:
                  type: string
                  description: The success message
      400:
        description: Missing 'username', 'password', or 'email' parameter
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
                  description: The error message
      500:
        description: Internal server error
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
                  description: The error message
      401:
        description: Unauthorized
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
                  description: The error message
      403:
        description: Forbidden
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
                  description: The error message
    security:
      - bearerAuth: [].
    """
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")
    organization = data.get("organization")
    is_admin = data.get("is_admin", False)
    sub = data.get("sub")  # Add OIDC subject identifier

    if not username or not password or not email:
        return jsonify({"error": "Username, password, and email are required"}), 400

    db_session = next(get_db())
    existing_user = db_session.query(User).filter(User.username == username).first()
    if existing_user:
        return jsonify({"error": "Username already exists"}), 400

    # Check if sub is provided and already exists
    if sub:
        existing_sub = db_session.query(User).filter(User.sub == sub).first()
        if existing_sub:
            return jsonify({"error": "User with this OIDC subject identifier already exists"}), 400

    # Hash the password and create the user in the application database
    password_hash = generate_password_hash(password)
    new_user = User(
        username=username,
        password_hash=password_hash,
        email=email,
        organization=organization,
        is_admin=is_admin,
        sub=sub,  # Add OIDC subject identifier
    )
    db_session.add(new_user)
    db_session.commit()

    # Authenticate with Guacamole API
    try:
        token = guacamole_login()
    except Exception as e:
        db_session.rollback()
        return (
            jsonify(
                {
                    "error": "Failed to authenticate with Guacamole API",
                    "details": str(e),
                }
            ),
            500,
        )

    # Create user in Guacamole
    try:
        create_guacamole_user(token, username, password)
    except Exception as e:
        db_session.rollback()
        return (
            jsonify({"error": "Failed to create user in Guacamole", "details": str(e)}),
            500,
        )

    # Assign user to appropriate groups in Guacamole
    try:
        if is_admin:
            ensure_admins_group(token)
            add_user_to_group(token, username, "admins")
        else:
            ensure_all_users_group(token)
            add_user_to_group(token, username, "all_users")
    except Exception as e:
        db_session.rollback()
        # Cleanup Guacamole user
        delete_guacamole_user(token, username)
        return (
            jsonify(
                {
                    "error": "Failed to assign user to group in Guacamole",
                    "details": str(e),
                }
            ),
            500,
        )

    return jsonify({"message": f"User '{username}' registered successfully."}), 201
