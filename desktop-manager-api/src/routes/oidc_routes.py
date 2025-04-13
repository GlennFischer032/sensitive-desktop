"""OIDC Authentication Routes.

This module implements the OIDC authentication flow with PKCE support.
It handles the OIDC authorization, callback, and token exchange.
"""

import base64
from datetime import datetime, timedelta
import hashlib
from http import HTTPStatus
import json
import logging
import secrets
from typing import Any
from urllib.parse import urlencode

from clients.factory import client_factory
from config.settings import get_settings
from database.core.session import get_db_session
from database.repositories.user import UserRepository
from flask import Blueprint, current_app, jsonify, request
import jwt
import requests


logger = logging.getLogger(__name__)
oidc_bp = Blueprint("oidc_bp", __name__)


def generate_pkce_pair() -> tuple[str, str]:
    """Generate PKCE code verifier and challenge.

    Returns:
        Tuple[str, str]: code_verifier, code_challenge
    """
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip("=")
    return code_verifier, code_challenge


def store_pkce_state(state: str, code_verifier: str) -> None:
    """Store PKCE state and code verifier in the database.

    Args:
        state: Random state value
        code_verifier: PKCE code verifier
    """
    with get_db_session() as session:
        user_repo = UserRepository(session)
        user_repo.create_pkce_state(state, code_verifier, datetime.utcnow() + timedelta(minutes=10))


def get_pkce_verifier(state: str) -> str:
    """Get PKCE code verifier for a given state.

    Args:
        state: State to look up

    Returns:
        str: Code verifier or None if not found

    Raises:
        ValueError: If state is invalid or expired
    """
    with get_db_session() as session:
        user_repo = UserRepository(session)
        pkce_state = user_repo.get_pkce_state(state)

        if not pkce_state:
            raise ValueError("Invalid or expired state")

        return pkce_state.code_verifier


@oidc_bp.route("/auth/oidc/login", methods=["GET"])
def oidc_login() -> tuple[dict[str, Any], int]:
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
            "scope": "openid profile email organization offline_access",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        authorization_url = f"{settings.OIDC_PROVIDER_URL}/authorize?{urlencode(auth_params)}"

        logger.info("OIDC authorization URL with scopes: %s", auth_params["scope"])

        return jsonify({"authorization_url": authorization_url}), HTTPStatus.OK

    except Exception as e:
        logger.error("Error initiating OIDC login: %s", str(e))
        return (
            jsonify({"error": "Failed to initiate OIDC login", "details": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@oidc_bp.route("/auth/oidc/callback", methods=["POST"])
def oidc_callback() -> tuple[dict[str, Any], int]:
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
        logger.info("Token response received (excluding sensitive information)")
        logger.info("Token response keys: %s", list(tokens.keys()))
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

        # Try to get additional user info from userinfo endpoint if available
        additional_user_info = {}
        try:
            userinfo_url = f"{settings.OIDC_PROVIDER_URL}/userinfo"
            userinfo_response = requests.get(
                userinfo_url, headers={"Authorization": f"Bearer {access_token}"}, timeout=10
            )
            if userinfo_response.status_code == 200:
                additional_user_info = userinfo_response.json()
                logger.info("Retrieved additional user info from userinfo endpoint")
                logger.info("UserInfo response keys: %s", list(additional_user_info.keys()))

                # Merge additional user info with ID token info, but don't overwrite existing values
                for key, value in additional_user_info.items():
                    if key not in user_info:
                        user_info[key] = value
        except Exception as e:
            logger.warning("Error fetching additional user info from userinfo endpoint: %s", str(e))

        # Extract user details from token
        sub = user_info.get("sub")
        email = user_info.get("email")

        # Log all name-related fields for debugging
        name_fields = {
            "name": user_info.get("name"),
            "given_name": user_info.get("given_name"),
            "family_name": user_info.get("family_name"),
            "nickname": user_info.get("nickname"),
            "preferred_username": user_info.get("preferred_username"),
        }
        logger.info(
            "Name-related fields found: %s",
            json.dumps({k: v for k, v in name_fields.items() if v}, indent=2),
        )

        # Get user's name with multiple fallbacks
        given_name = user_info.get("given_name", "")
        family_name = user_info.get("family_name", "")

        # Use name from token or construct it from given_name + family_name
        if user_info.get("name"):
            name = user_info.get("name")
        elif given_name or family_name:
            name = f"{given_name} {family_name}".strip()
        else:
            name = None

        locale = user_info.get("locale")
        email_verified = user_info.get("email_verified", False)

        organization = user_info.get("organization")

        # Log the full user info for debugging
        logger.info(
            "OIDC token decoded with user info: %s",
            json.dumps({k: v for k, v in user_info.items() if k not in ["at_hash", "auth_time"]}, indent=2),
        )

        # Log the extracted user details
        logger.info(
            "Extracted user details from OIDC token: sub=%s, email=%s, organization=%s",
            sub,
            email,
            organization,
        )

        with get_db_session() as session:
            user_repo = UserRepository(session)
            user = user_repo.get_by_sub(sub)

            if not user:
                return jsonify({"error": "User not found"}), HTTPStatus.BAD_REQUEST

            user_repo.update_user(
                user.id,
                {
                    "given_name": given_name,
                    "family_name": family_name,
                    "name": name,
                    "email": email,
                    "organization": organization,
                    "locale": locale,
                    "email_verified": email_verified,
                    "last_login": datetime.utcnow(),
                },
            )
            guacamole_client = client_factory.get_guacamole_client()
            guacamole_client.update_user(
                token=guacamole_client.login(),
                username=user.username,
                attributes={
                    "access-window-start": "",
                    "access-window-end": "",
                    "disabled": "",
                    "expired": "",
                    "timezone": None,
                    "guac-email-address": email,
                    "guac-full-name": name,
                    "guac-organization": organization,
                    "guac-organizational-role": None,
                    "valid-from": "",
                    "valid-until": "",
                },
            )

            association = user_repo.get_social_auth(provider="oidc", provider_user_id=sub)

            if not association:
                # Create new social auth association
                user_repo.create_social_auth(
                    {
                        "user_id": user.id,
                        "provider": "oidc",
                        "provider_user_id": sub,
                        "extra_data": json.dumps({"id_token": id_token, "access_token": access_token}),
                        "created_at": datetime.utcnow(),
                    },
                )
            else:
                # Update social auth association
                user_repo.update_social_auth_last_used(association.id)

            # Create access token for our API
            exp_time = datetime.utcnow() + timedelta(hours=24)
            payload = {
                "sub": sub,
                "name": user.username,
                "iat": datetime.utcnow(),
                "exp": exp_time,
                "admin": user.is_admin,
            }
            api_token = jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")

            # Return user info and token
            return (
                jsonify(
                    {
                        "token": api_token,
                        "user": {
                            "id": user.id,
                            "username": user.username,
                            "email": user.email,
                            "is_admin": user.is_admin,
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
