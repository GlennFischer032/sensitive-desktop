"""API routes for user management.

This module provides API endpoints for managing users, separate from UI routes.
"""

from flask import current_app, jsonify, request, session
from http import HTTPStatus

from app.clients.base import APIError
from app.clients.factory import client_factory
from app.middleware.auth import admin_required, login_required

from . import users_api_bp


@users_api_bp.route("/", methods=["GET"])
@login_required
@admin_required
def list_users():
    """Get a list of all users.
    ---
    tags:
      - Users API
    responses:
      200:
        description: A list of users
        schema:
          type: object
          properties:
            users:
              type: array
              items:
                type: object
                properties:
                  username:
                    type: string
                  is_admin:
                    type: boolean
                  email:
                    type: string
      403:
        description: Forbidden - User is not an administrator
      500:
        description: Server error
    """
    if not session.get("is_admin", False):
        return jsonify({"error": "Administrator privileges required"}), HTTPStatus.FORBIDDEN

    try:
        current_app.logger.info("API: Fetching users list")
        users_client = client_factory.get_users_client()
        users = users_client.list_users()

        return jsonify({"users": users}), HTTPStatus.OK
    except APIError as e:
        current_app.logger.error(f"API Error fetching users: {e.message}")
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        current_app.logger.error(f"API Error fetching users: {str(e)}")
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@users_api_bp.route("/<username>", methods=["GET"])
@login_required
@admin_required
def get_user(username):
    """Get details for a specific user.
    ---
    tags:
      - Users API
    parameters:
      - name: username
        in: path
        type: string
        required: true
        description: Username of the user to get details for
    responses:
      200:
        description: User details
        schema:
          type: object
          properties:
            user:
              type: object
              properties:
                username:
                  type: string
                is_admin:
                  type: boolean
                email:
                  type: string
            user_connections:
              type: array
              items:
                type: object
      404:
        description: User not found
      500:
        description: Server error
    """
    try:
        current_app.logger.info(f"API: Fetching details for user: {username}")
        users_client = client_factory.get_users_client()
        user = users_client.get_user(username)

        # Get user's connections if available
        try:
            connections_client = client_factory.get_connections_client()
            user_connections = connections_client.list_connections(username)
        except Exception as e:
            current_app.logger.warning(f"Could not fetch connections for user {username}: {str(e)}")
            user_connections = []

        return jsonify({"user": user, "user_connections": user_connections}), HTTPStatus.OK
    except APIError as e:
        current_app.logger.error(f"API Error fetching user details: {e.message}")
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        current_app.logger.error(f"API Error fetching user details: {str(e)}")
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@users_api_bp.route("/", methods=["POST"])
@login_required
@admin_required
def create_user():
    """Create a new user.
    ---
    tags:
      - Users API
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - username
            - sub
          properties:
            username:
              type: string
              description: Username for the new user
            is_admin:
              type: boolean
              description: Whether the user is an administrator
            sub:
              type: string
              description: OIDC Subject Identifier
    responses:
      201:
        description: User created successfully
        schema:
          type: object
          properties:
            message:
              type: string
            user:
              type: object
      400:
        description: Invalid request data
      500:
        description: Server error
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), HTTPStatus.BAD_REQUEST

        username = data.get("username")
        sub = data.get("sub")
        is_admin = data.get("is_admin", False)

        if not username or not sub:
            return jsonify({"error": "Username and OIDC Subject Identifier are required"}), HTTPStatus.BAD_REQUEST

        user_data = {"username": username, "is_admin": is_admin, "sub": sub}

        current_app.logger.info(f"API: Adding new user: {username}")
        users_client = client_factory.get_users_client()
        users_client.add_user(**user_data)

        return jsonify(
            {"message": "User created successfully", "user": {"username": username, "is_admin": is_admin, "sub": sub}}
        ), HTTPStatus.CREATED

    except APIError as e:
        current_app.logger.error(f"API Error creating user: {e.message}")
        if e.details:
            return jsonify({"error": e.message, "details": e.details}), e.status_code
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        current_app.logger.error(f"API Error creating user: {str(e)}")
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@users_api_bp.route("/<username>", methods=["DELETE"])
@login_required
@admin_required
def delete_user(username):
    """Delete a user.
    ---
    tags:
      - Users API
    parameters:
      - name: username
        in: path
        type: string
        required: true
        description: Username of the user to delete
    responses:
      200:
        description: User deleted successfully
        schema:
          type: object
          properties:
            message:
              type: string
      400:
        description: Cannot delete your own account
      404:
        description: User not found
      500:
        description: Server error
    """
    try:
        current_app.logger.info(f"API: Attempting to delete user: {username}")

        # Check if user is trying to delete their own account
        if username == session.get("username"):
            return jsonify({"error": "Cannot delete your own account"}), HTTPStatus.BAD_REQUEST

        users_client = client_factory.get_users_client()
        users_client.delete_user(username)

        return jsonify({"message": "User deleted successfully"}), HTTPStatus.OK

    except APIError as e:
        current_app.logger.error(f"API Error deleting user: {e.message}")
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        current_app.logger.error(f"API Error deleting user: {str(e)}")
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR
