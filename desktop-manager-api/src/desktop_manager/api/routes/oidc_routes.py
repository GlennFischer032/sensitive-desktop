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

from desktop_manager.api.models.base import get_db
from desktop_manager.api.models.user import PKCEState, SocialAuthAssociation, User
from desktop_manager.clients.guacamole import (
    add_user_to_group,
    copy_user_permissions,
    create_guacamole_user,
    ensure_all_users_group,
    guacamole_login,
    update_guacamole_user,
)
from desktop_manager.config.settings import get_settings


logger = logging.getLogger(__name__)
oidc_bp = Blueprint("oidc_bp", __name__)


def generate_pkce_pair() -> Tuple[str, str]:
    """Generate PKCE code verifier and challenge pair."""
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return code_verifier, code_challenge


def store_pkce_state(db_session, state: str, code_verifier: str) -> None:
    """Store PKCE state and code verifier."""
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    pkce_state = PKCEState(state=state, code_verifier=code_verifier, expires_at=expires_at)
    db_session.add(pkce_state)
    db_session.commit()


def get_pkce_verifier(db_session, state: str) -> str:
    """Get and invalidate PKCE code verifier."""
    pkce_state = (
        db_session.query(PKCEState)
        .filter(
            PKCEState.state == state,
            PKCEState.used == False,  # noqa: E712
            PKCEState.expires_at > datetime.utcnow(),
        )
        .first()
    )

    if not pkce_state:
        return None

    pkce_state.used = True
    db_session.commit()
    return pkce_state.code_verifier


@oidc_bp.route("/auth/oidc/login", methods=["GET"])
def oidc_login() -> Tuple[Dict[str, Any], int]:
    """Initiate OIDC authentication flow with PKCE.

    This endpoint generates PKCE parameters and redirects to the OIDC provider's
    authorization endpoint.

    Returns:
        tuple: Authorization URL and state
    """
    try:
        # Generate PKCE parameters
        code_verifier, code_challenge = generate_pkce_pair()
        state = secrets.token_urlsafe(32)

        # Store PKCE state
        db_session = next(get_db())
        try:
            store_pkce_state(db_session, state, code_verifier)
        finally:
            db_session.close()

        # Get settings
        settings = get_settings()

        # Get the frontend callback URL from settings
        frontend_callback = settings.OIDC_REDIRECT_URI

        # If we're in production and the URL contains localhost, use the frontendUrl from settings
        if "localhost" in frontend_callback and os.environ.get("FLASK_ENV") == "production":
            frontend_callback = f"{settings.FRONTEND_URL}/auth/oidc/callback"

        logger.info("Using frontend callback URL: %s", frontend_callback)

        # Build authorization URL with frontend callback
        params = {
            "response_type": "code",
            "client_id": settings.OIDC_CLIENT_ID,
            "redirect_uri": frontend_callback,
            "scope": "openid email profile organization",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        auth_url = f"{settings.OIDC_PROVIDER_URL}/authorize?{urlencode(params)}"

        return (
            jsonify(
                {
                    "auth_url": auth_url,
                    "state": state,
                    "redirect_uri": frontend_callback,
                }
            ),
            HTTPStatus.OK,
        )

    except Exception as e:
        logger.error("Error initiating OIDC flow: %s", str(e))
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@oidc_bp.route("/auth/oidc/callback", methods=["POST"])
def oidc_callback() -> Tuple[Dict[str, Any], int]:
    """Handle OIDC callback and token exchange.

    This endpoint exchanges the authorization code for tokens and creates/updates
    the user record.

    Returns:
        tuple: JWT token response or error
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON payload"}), HTTPStatus.BAD_REQUEST

        code = data.get("code")
        state = data.get("state")
        redirect_uri = data.get("redirect_uri")  # Get the redirect URI from the request

        if not code or not state or not redirect_uri:
            return (
                jsonify({"error": "Missing code, state, or redirect_uri parameter"}),
                HTTPStatus.BAD_REQUEST,
            )

        # Get and validate PKCE verifier
        db_session = next(get_db())
        try:
            code_verifier = get_pkce_verifier(db_session, state)
            if not code_verifier:
                return (
                    jsonify({"error": "Invalid or expired state"}),
                    HTTPStatus.BAD_REQUEST,
                )

            # Get settings
            settings = get_settings()

            # Log the redirect URI being used
            logger.info("Using redirect URI for token exchange: %s", redirect_uri)

            # Exchange code for tokens using the same redirect URI as authorization
            token_response = requests.post(
                f"{settings.OIDC_PROVIDER_URL}/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,  # Use the same redirect URI as authorization
                    "client_id": settings.OIDC_CLIENT_ID,
                    "client_secret": settings.OIDC_CLIENT_SECRET,
                    "code_verifier": code_verifier,
                },
                timeout=10,
            )

            if token_response.status_code != 200:
                logger.error("Token exchange failed: %s", token_response.text)
                return (
                    jsonify({"error": "Token exchange failed"}),
                    HTTPStatus.BAD_GATEWAY,
                )

            tokens = token_response.json()

            # Get user info
            userinfo_response = requests.get(
                f"{settings.OIDC_PROVIDER_URL}/userinfo",
                headers={"Authorization": f"Bearer {tokens['access_token']}"},
                timeout=10,
            )
            userinfo_response.raise_for_status()
            userinfo = userinfo_response.json()

            # Find or create user - use sub instead of email for lookup
            user = db_session.query(User).filter(User.sub == userinfo["sub"]).first()

            if user:
                # Check if username has changed
                old_username = user.username
                username_changed = False

                # Update existing user in desktop manager
                user.email = userinfo["email"]  # Update email in case it changed
                user.given_name = userinfo.get("given_name")
                user.family_name = userinfo.get("family_name")
                user.locale = userinfo.get("locale")
                user.email_verified = userinfo.get("email_verified", False)
                user.last_login = datetime.utcnow()

                # Update username and organization if provided
                if userinfo.get("preferred_username"):
                    if user.username != userinfo.get("preferred_username"):
                        username_changed = True
                        old_username = user.username
                        user.username = userinfo.get("preferred_username")
                if userinfo.get("organization"):
                    user.organization = userinfo.get("organization")

                # Update user in Guacamole
                try:
                    # Prepare Guacamole attributes
                    guacamole_attributes = {
                        "guac-full-name": f"{userinfo.get('given_name', '')} {userinfo.get('family_name', '')}".strip()
                        or user.username,
                        "guac-email-address": user.email,
                        "guac-organization": user.organization or "",
                    }

                    # If username has changed, we need to handle this special case
                    if username_changed:
                        logger.info("Username changed from %s to %s", old_username, user.username)

                        # Get a Guacamole admin token instead of using the OIDC token
                        try:
                            guac_token = guacamole_login()
                            logger.info("Obtained Guacamole admin token for user operations")
                        except Exception as login_error:
                            logger.error("Failed to login to Guacamole: %s", str(login_error))
                            guac_token = None

                        # Only proceed if we got a valid Guacamole token
                        if guac_token:
                            try:
                                # Try to create a new user with the new username
                                create_guacamole_user(
                                    guac_token, user.username, "", guacamole_attributes
                                )
                                logger.info(
                                    "Created new Guacamole user with updated username: %s",
                                    user.username,
                                )

                                # Copy permissions from old user to new user
                                try:
                                    # Copy all permissions from old user to new user
                                    copy_user_permissions(guac_token, old_username, user.username)
                                    logger.info(
                                        "Successfully copied permissions from %s to %s",
                                        old_username,
                                        user.username,
                                    )
                                except Exception as perm_error:
                                    logger.error(
                                        "Failed to copy permissions from %s to %s: %s",
                                        old_username,
                                        user.username,
                                        str(perm_error),
                                    )
                                    logger.warning(
                                        "Username changed from %s to %s. Permissions may need to be manually transferred.",
                                        old_username,
                                        user.username,
                                    )

                                # Add the new user to the all_users group
                                ensure_all_users_group(guac_token)
                                add_user_to_group(guac_token, user.username, "all_users")
                                logger.info("Added user %s to all_users group", user.username)

                            except Exception as create_error:
                                logger.error(
                                    "Failed to create new Guacamole user: %s", str(create_error)
                                )
                                # If we can't create a new user, just update the existing one
                                try:
                                    guac_token = guacamole_login()
                                    logger.info("Obtained Guacamole admin token for user update")
                                    update_guacamole_user(
                                        guac_token, old_username, guacamole_attributes
                                    )
                                    logger.info("Updated existing Guacamole user: %s", old_username)
                                except Exception as e:
                                    logger.error(
                                        "Failed to update existing user in Guacamole: %s", str(e)
                                    )
                        else:
                            logger.error(
                                "Could not perform Guacamole user operations: No valid admin token"
                            )
                    else:
                        # Just update the existing user
                        try:
                            guac_token = guacamole_login()
                            logger.info("Obtained Guacamole admin token for user update")
                            update_guacamole_user(guac_token, user.username, guacamole_attributes)
                            logger.info("Updated user %s in Guacamole", user.username)
                        except Exception as e:
                            logger.error("Failed to update user in Guacamole: %s", str(e))
                except Exception as e:
                    logger.error("Failed to update user in Guacamole: %s", str(e))
                    # Continue with authentication even if Guacamole update fails
            else:
                # Create new user
                preferred_username = userinfo.get(
                    "preferred_username", userinfo["email"].split("@")[0]
                )
                user = User(
                    username=preferred_username,
                    email=userinfo["email"],
                    organization=userinfo.get("organization"),
                    sub=userinfo["sub"],
                    given_name=userinfo.get("given_name"),
                    family_name=userinfo.get("family_name"),
                    locale=userinfo.get("locale"),
                    email_verified=userinfo.get("email_verified", False),
                    last_login=datetime.utcnow(),
                )
                db_session.add(user)

                # Add to Guacamole all_users group
                ensure_all_users_group(tokens["access_token"])

                # Create user in Guacamole with attributes
                try:
                    # Get a Guacamole admin token instead of using the OIDC token
                    try:
                        guac_token = guacamole_login()
                        logger.info("Obtained Guacamole admin token for user creation")
                    except Exception as login_error:
                        logger.error("Failed to login to Guacamole: %s", str(login_error))
                        guac_token = None

                    if guac_token:
                        # Prepare Guacamole attributes
                        guacamole_attributes = {
                            "guac-full-name": f"{userinfo.get('given_name', '')} {userinfo.get('family_name', '')}".strip()
                            or preferred_username,
                            "guac-email-address": userinfo["email"],
                            "guac-organization": userinfo.get("organization", ""),
                            "disabled": "",  # Not disabled
                            "expired": "",  # Not expired
                        }

                        # Create user in Guacamole with empty password (will use OIDC)
                        create_guacamole_user(
                            guac_token, preferred_username, "", guacamole_attributes
                        )
                        add_user_to_group(guac_token, preferred_username, "all_users")
                        current_app.logger.info("Created user %s in Guacamole", preferred_username)
                    else:
                        current_app.logger.error(
                            "Could not create Guacamole user: No valid admin token"
                        )
                except Exception as e:
                    current_app.logger.error("Failed to create user in Guacamole: %s", str(e))
                    # Continue with authentication even if Guacamole creation fails

            # Update or create social auth association
            social_auth = (
                db_session.query(SocialAuthAssociation)
                .filter(
                    SocialAuthAssociation.provider == "oidc",
                    SocialAuthAssociation.provider_user_id == userinfo["sub"],
                )
                .first()
            )

            if not social_auth:
                social_auth = SocialAuthAssociation(
                    user=user,
                    provider="oidc",
                    provider_user_id=userinfo["sub"],
                    provider_name="e-infra",
                    extra_data=userinfo,
                )
                db_session.add(social_auth)
            else:
                social_auth.last_used = datetime.utcnow()
                social_auth.extra_data = userinfo

            db_session.commit()

            # Generate JWT token
            token_data = {
                "user_id": user.id,
                "username": user.username,
                "is_admin": user.is_admin,
                "exp": datetime.utcnow() + timedelta(hours=1),
            }
            jwt_token = jwt.encode(token_data, settings.SECRET_KEY, algorithm="HS256")

            return (
                jsonify(
                    {
                        "token": jwt_token,
                        "is_admin": user.is_admin,
                        "username": user.username,
                        "email": user.email,
                        "organization": user.organization,
                        "sub": user.sub,
                    }
                ),
                HTTPStatus.OK,
            )

        finally:
            db_session.close()

    except requests.exceptions.RequestException as e:
        logger.error("OIDC provider error: %s", str(e))
        return jsonify({"error": "OIDC provider error"}), HTTPStatus.BAD_GATEWAY

    except Exception as e:
        logger.error("Error handling OIDC callback: %s", str(e))
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR
