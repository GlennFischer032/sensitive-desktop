"""OIDC Authentication Routes.

This module implements the OIDC authentication flow with PKCE support.
It handles the OIDC authorization, callback, and token exchange.
"""

import base64
from datetime import datetime, timedelta
import hashlib
from http import HTTPStatus
import logging
import os
import secrets
from typing import Any, Dict, Tuple
from urllib.parse import urlencode

from flask import Blueprint, current_app, jsonify, request
import jwt
import requests

from desktop_manager.api.models.user import PKCEState, SocialAuthAssociation, User
from desktop_manager.clients.factory import client_factory
from desktop_manager.config.settings import get_settings


logger = logging.getLogger(__name__)
oidc_bp = Blueprint("oidc_bp", __name__)


def ensure_all_users_group(guacamole_client):
    """Ensure 'All Users' group exists in Guacamole.

    Args:
        guacamole_client: A GuacamoleClient instance

    Returns:
        str: The ID of the all users group
    """
    group_name = "All Users"
    return guacamole_client.ensure_group(group_name)


def generate_pkce_pair() -> Tuple[str, str]:
    """Generate PKCE code verifier and challenge.

    Returns:
        Tuple[str, str]: code_verifier, code_challenge
    """
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    return code_verifier, code_challenge


def store_pkce_state(state: str, code_verifier: str) -> None:
    """Store PKCE state and code verifier in the database.

    Args:
        state: Random state value
        code_verifier: PKCE code verifier
    """
    db_client = client_factory.get_database_client()
    expires_at = datetime.utcnow() + timedelta(minutes=10)

    query = """
    INSERT INTO pkce_states (state, code_verifier, expires_at)
    VALUES (:state, :code_verifier, :expires_at)
    """

    db_client.execute_query(
        query, {"state": state, "code_verifier": code_verifier, "expires_at": expires_at}
    )


def get_pkce_verifier(state: str) -> str:
    """Get PKCE code verifier for a given state.

    Args:
        state: State to look up

    Returns:
        str: Code verifier or None if not found

    Raises:
        ValueError: If state is invalid or expired
    """
    db_client = client_factory.get_database_client()

    # Get code verifier and delete the record
    query = """
    DELETE FROM pkce_states
    WHERE state = :state AND expires_at > :now
    RETURNING code_verifier
    """

    result, count = db_client.execute_query(query, {"state": state, "now": datetime.utcnow()})

    if count == 0:
        raise ValueError("Invalid or expired state")

    return result[0]["code_verifier"]


@oidc_bp.route("/auth/oidc/login", methods=["GET"])
def oidc_login() -> Tuple[Dict[str, Any], int]:
    """Initiate OIDC login flow.

    This endpoint starts the OIDC authentication flow by generating
    necessary PKCE parameters and redirecting to the OIDC provider.

    Returns:
        tuple: A tuple containing:
            - Dict with authorization URL
            - HTTP status code
    """
    try:
        settings = get_settings()

        # Generate PKCE code verifier and challenge
        code_verifier, code_challenge = generate_pkce_pair()

        # Generate state for CSRF protection
        state = secrets.token_urlsafe(32)

        # Store state and code verifier in database
        store_pkce_state(state, code_verifier)

        # Build authorization URL
        auth_params = {
            "response_type": "code",
            "client_id": settings.OIDC_CLIENT_ID,
            "redirect_uri": settings.OIDC_REDIRECT_URI,
            "scope": "openid email profile",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        authorization_url = f"{settings.OIDC_PROVIDER_URL}/auth?{urlencode(auth_params)}"

        return jsonify({"authorization_url": authorization_url}), HTTPStatus.OK

    except Exception as e:
        logger.error("Error initiating OIDC login: %s", str(e))
        return (
            jsonify({"error": "Failed to initiate OIDC login", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@oidc_bp.route("/auth/oidc/callback", methods=["POST"])
def oidc_callback() -> Tuple[Dict[str, Any], int]:
    """Handle OIDC callback.

    This endpoint handles the callback from the OIDC provider,
    exchanges the authorization code for tokens, and authenticates
    or creates the user in the local database.

    Returns:
        tuple: A tuple containing:
            - Dict with authentication result
            - HTTP status code
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing request data"}), HTTPStatus.BAD_REQUEST

        code = data.get("code")
        state = data.get("state")

        if not code or not state:
            return (
                jsonify({"error": "Missing required parameters"}),
                HTTPStatus.BAD_REQUEST,
            )

        # Get code verifier for this state
        try:
            code_verifier = get_pkce_verifier(state)
        except ValueError as e:
            logger.error("Invalid state: %s", str(e))
            return jsonify({"error": str(e)}), HTTPStatus.BAD_REQUEST

        # Exchange code for tokens
        settings = get_settings()
        token_url = f"{settings.OIDC_PROVIDER_URL}/token"
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": settings.OIDC_REDIRECT_URI,
            "client_id": settings.OIDC_CLIENT_ID,
            "client_secret": settings.OIDC_CLIENT_SECRET,
            "code_verifier": code_verifier,
        }

        token_response = requests.post(token_url, data=token_data, timeout=10)
        if token_response.status_code != 200:
            logger.error(
                "Token exchange failed: %s - %s",
                token_response.status_code,
                token_response.text,
            )
            return (
                jsonify({"error": "Token exchange failed", "details": token_response.text}),
                HTTPStatus.BAD_REQUEST,
            )

        tokens = token_response.json()
        access_token = tokens.get("access_token")
        id_token = tokens.get("id_token")

        if not access_token or not id_token:
            return (
                jsonify({"error": "Invalid token response"}),
                HTTPStatus.BAD_REQUEST,
            )

        # Get user info from ID token
        user_info = jwt.decode(
            id_token,
            options={"verify_signature": False},
            algorithms=["RS256"],
        )

        # Get user from database or create new user
        db_client = client_factory.get_database_client()

        # Extract user details from token
        sub = user_info.get("sub")
        email = user_info.get("email")
        name = user_info.get("name")
        preferred_username = user_info.get("preferred_username") or email
        user_info.get("locale")
        user_info.get("email_verified", False)

        # Find user by sub (OIDC unique identifier)
        query = "SELECT * FROM users WHERE sub = :sub"
        users, count = db_client.execute_query(query, {"sub": sub})

        if count > 0:
            user = users[0]
            user_exists = True
        else:
            # If no user found by sub, try to find by email
            query = "SELECT * FROM users WHERE email = :email"
            users, count = db_client.execute_query(query, {"email": email})

            if count > 0:
                user = users[0]
                user_exists = True

                # Update the sub field for this user
                update_query = "UPDATE users SET sub = :sub WHERE id = :user_id"
                db_client.execute_query(update_query, {"sub": sub, "user_id": user["id"]})
            else:
                user_exists = False

        if user_exists:
            # Update user information
            update_query = """
            UPDATE users SET
                name = :name,
                email = :email,
                last_login = :last_login
            WHERE id = :user_id
            """

            db_client.execute_query(
                update_query,
                {
                    "name": name,
                    "email": email,
                    "last_login": datetime.utcnow(),
                    "user_id": user["id"],
                },
            )

            # Check if user has social auth association
            query = """
            SELECT * FROM social_auth_associations
            WHERE user_id = :user_id AND provider_name = 'oidc'
            """

            associations, count = db_client.execute_query(query, {"user_id": user["id"]})

            if count == 0:
                # Create social auth association
                insert_query = """
                INSERT INTO social_auth_associations
                (user_id, provider_name, provider_user_id, last_used, extra_data)
                VALUES (:user_id, :provider_name, :provider_user_id, :last_used, :extra_data)
                """

                db_client.execute_query(
                    insert_query,
                    {
                        "user_id": user["id"],
                        "provider_name": "oidc",
                        "provider_user_id": sub,
                        "last_used": datetime.utcnow(),
                        "extra_data": {"id_token": id_token, "access_token": access_token},
                    },
                )
            else:
                # Update social auth association
                update_query = """
                UPDATE social_auth_associations
                SET last_used = :last_used, extra_data = :extra_data
                WHERE user_id = :user_id AND provider_name = 'oidc'
                """

                db_client.execute_query(
                    update_query,
                    {
                        "last_used": datetime.utcnow(),
                        "extra_data": {"id_token": id_token, "access_token": access_token},
                        "user_id": user["id"],
                    },
                )
        else:
            # Create new user
            username = generate_unique_username(preferred_username)

            insert_query = """
            INSERT INTO users
            (username, email, name, sub, is_admin, created_at, last_login)
            VALUES (:username, :email, :name, :sub, :is_admin, :created_at, :last_login)
            RETURNING id
            """

            result, _ = db_client.execute_query(
                insert_query,
                {
                    "username": username,
                    "email": email,
                    "name": name,
                    "sub": sub,
                    "is_admin": False,  # New users from OIDC are not admins by default
                    "created_at": datetime.utcnow(),
                    "last_login": datetime.utcnow(),
                },
            )

            user_id = result[0]["id"]

            # Create social auth association
            insert_query = """
            INSERT INTO social_auth_associations
            (user_id, provider_name, provider_user_id, last_used, extra_data)
            VALUES (:user_id, :provider_name, :provider_user_id, :last_used, :extra_data)
            """

            db_client.execute_query(
                insert_query,
                {
                    "user_id": user_id,
                    "provider_name": "oidc",
                    "provider_user_id": sub,
                    "last_used": datetime.utcnow(),
                    "extra_data": {"id_token": id_token, "access_token": access_token},
                },
            )

            # Fetch the created user
            query = "SELECT * FROM users WHERE id = :user_id"
            users, _ = db_client.execute_query(query, {"user_id": user_id})
            user = users[0]

        # Create access token for our API
        exp_time = datetime.utcnow() + timedelta(hours=24)
        payload = {
            "sub": user["id"],
            "name": user["username"],
            "iat": datetime.utcnow(),
            "exp": exp_time,
            "admin": user["is_admin"],
        }
        api_token = jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")

        # Return user info and token
        return (
            jsonify(
                {
                    "token": api_token,
                    "user": {
                        "id": user["id"],
                        "username": user["username"],
                        "email": user["email"],
                        "is_admin": user["is_admin"],
                    },
                }
            ),
            HTTPStatus.OK,
        )

    except Exception as e:
        logger.error("Error processing OIDC callback: %s", str(e))
        return (
            jsonify({"error": "Failed to process OIDC callback", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


def generate_unique_username(base_username: str) -> str:
    """Generate a unique username.

    Args:
        base_username: Base username to start with

    Returns:
        str: Unique username
    """
    db_client = client_factory.get_database_client()
    username = base_username
    suffix = 1

    while True:
        query = "SELECT COUNT(*) as count FROM users WHERE username = :username"
        result, _ = db_client.execute_query(query, {"username": username})

        if result[0]["count"] == 0:
            return username

        username = f"{base_username}{suffix}"
        suffix += 1
