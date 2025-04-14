import base64
from datetime import datetime, timedelta
import hashlib
import json
import logging
import secrets
from typing import Any
from urllib.parse import urlencode

from clients.factory import client_factory
from config.settings import get_settings
from database.repositories.user import UserRepository
import jwt
import requests
from services.connections import APIError, BadRequestError, ForbiddenError, NotFoundError


class UserService:
    """Service for managing users and authentication."""

    def generate_pkce_pair(self) -> tuple[str, str]:
        """Generate PKCE code verifier and challenge.

        Returns:
            Tuple[str, str]: code_verifier, code_challenge
        """
        code_verifier = secrets.token_urlsafe(64)
        code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip("=")
        return code_verifier, code_challenge

    def store_pkce_state(self, state: str, code_verifier: str, session) -> None:
        """Store PKCE state and code verifier in the database.

        Args:
            state: Random state value
            code_verifier: PKCE code verifier
            session: Database session
        """
        user_repo = UserRepository(session)
        user_repo.create_pkce_state(state, code_verifier, datetime.utcnow() + timedelta(minutes=10))

    def get_pkce_verifier(self, state: str, session) -> str:
        """Get PKCE code verifier for a given state.

        Args:
            state: State to look up
            session: Database session

        Returns:
            str: Code verifier or None if not found

        Raises:
            ValueError: If state is invalid or expired
        """
        user_repo = UserRepository(session)
        pkce_state = user_repo.get_pkce_state(state)

        if not pkce_state:
            raise ValueError("Invalid or expired state")

        return pkce_state.code_verifier

    def initiate_oidc_login(self, session) -> dict[str, Any]:
        """Initiate OIDC login flow.

        Args:
            session: Database session

        Returns:
            Dict with authorization URL
        """
        try:
            settings = get_settings()

            # Generate PKCE code verifier and challenge
            code_verifier, code_challenge = self.generate_pkce_pair()

            # Generate state for CSRF protection
            state = secrets.token_urlsafe(32)

            # Store state and code verifier in database
            self.store_pkce_state(state, code_verifier, session)

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

            logging.info("OIDC authorization URL with scopes: %s", auth_params["scope"])

            return {"authorization_url": authorization_url}
        except Exception as e:
            logging.error("Error initiating OIDC login: %s", str(e))
            raise APIError(f"Failed to initiate OIDC login: {e!s}") from e

    def process_oidc_callback(self, code, state, app_secret_key, session) -> dict[str, Any]:
        """Process OIDC callback.

        Args:
            code: Authorization code from OIDC provider
            state: State from OIDC provider
            app_secret_key: Application secret key for JWT generation
            session: Database session

        Returns:
            Dict with authentication result

        Raises:
            BadRequestError: If request data is invalid
            APIError: If an error occurs during processing
        """
        try:
            if not code or not state:
                raise BadRequestError("Missing required parameters")

            # Get code verifier for this state
            try:
                code_verifier = self.get_pkce_verifier(state, session)
            except ValueError as e:
                logging.error("Invalid state: %s", str(e))
                raise BadRequestError(str(e)) from e

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
                logging.error(
                    "Token exchange failed: %s - %s",
                    token_response.status_code,
                    token_response.text,
                )
                raise BadRequestError(f"Token exchange failed: {token_response.text}")

            tokens = token_response.json()
            logging.info("Token response received (excluding sensitive information)")
            logging.info("Token response keys: %s", list(tokens.keys()))
            access_token = tokens.get("access_token")
            id_token = tokens.get("id_token")

            if not access_token or not id_token:
                raise BadRequestError("Invalid token response")

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
                    logging.info("Retrieved additional user info from userinfo endpoint")
                    logging.info("UserInfo response keys: %s", list(additional_user_info.keys()))

                    # Merge additional user info with ID token info, but don't overwrite existing values
                    for key, value in additional_user_info.items():
                        if key not in user_info:
                            user_info[key] = value
            except Exception as e:
                logging.warning("Error fetching additional user info from userinfo endpoint: %s", str(e))

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
            logging.info(
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
            logging.info(
                "OIDC token decoded with user info: %s",
                json.dumps({k: v for k, v in user_info.items() if k not in ["at_hash", "auth_time"]}, indent=2),
            )

            # Log the extracted user details
            logging.info(
                "Extracted user details from OIDC token: sub=%s, email=%s, organization=%s",
                sub,
                email,
                organization,
            )

            user_repo = UserRepository(session)
            user = user_repo.get_by_sub(sub)

            if not user:
                raise BadRequestError("User not found")

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

            # Update user in Guacamole
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
            api_token = jwt.encode(payload, app_secret_key, algorithm="HS256")

            # Return user info and token
            return {
                "token": api_token,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "is_admin": user.is_admin,
                },
            }
        except APIError:
            # Re-raise API errors
            raise
        except Exception as e:
            logging.error("Error processing OIDC callback: %s", str(e))
            raise APIError(f"Failed to process OIDC callback: {e!s}") from e

    def remove_user(self, username, current_user, session) -> dict[str, Any]:
        """Remove a user from the system.

        Args:
            username: Username of the user to remove
            current_user: Current authenticated user
            session: Database session

        Returns:
            Dict with success message

        Raises:
            BadRequestError: If request data is invalid
            NotFoundError: If user is not found
            ForbiddenError: If current user is trying to remove their own account
            APIError: If an error occurs during processing
        """
        try:
            if not username:
                raise BadRequestError("Missing username in request data")

            logging.info("Request to remove user: %s", username)

            if current_user.username == username:
                raise ForbiddenError("You cannot remove your own account")

            user_repo = UserRepository(session)
            user = user_repo.get_by_username(username)
            if not user:
                raise NotFoundError("User not found")

            try:
                logging.info("Removing user from Guacamole: %s", username)
                guacamole_client = client_factory.get_guacamole_client()
                token = guacamole_client.login()
                guacamole_client.delete_user(token, username)
                logging.info("Successfully removed user from Guacamole: %s", username)
            except Exception as e:
                logging.error("Failed to remove user from Guacamole: %s", str(e))

            user_repo.delete_user(user.id)
            logging.info("Successfully removed user from database: %s", username)

            return {"message": "User removed successfully"}
        except APIError:
            # Re-raise API errors
            raise
        except Exception as e:
            logging.error("Error removing user: %s", str(e))
            raise APIError(f"Failed to remove user: {e!s}") from e

    def create_user(self, data, session) -> dict[str, Any]:
        """Create a new user.

        Args:
            data: User data
            session: Database session

        Returns:
            Dict with created user info

        Raises:
            BadRequestError: If request data is invalid
            APIError: If an error occurs during processing
        """
        try:
            if not data:
                raise BadRequestError("Missing request data")

            # Check for required fields
            username = data.get("username")
            sub = data.get("sub")
            is_admin = data.get("is_admin", False)

            if not username or not sub:
                raise BadRequestError("Username and sub are required")

            if len(username) < 3:
                raise BadRequestError("Username must be at least 3 characters long")

            user_repo = UserRepository(session)
            existing_users = user_repo.get_by_username(username) or user_repo.get_by_sub(sub)

            if existing_users:
                # Check which field already exists
                if existing_users.username == username:
                    raise BadRequestError("Username already exists")
                if existing_users.sub == sub:
                    raise BadRequestError("User with this OIDC subject already exists")

            # Create minimal user with just username and sub
            # Other fields will be populated during the first OIDC login
            user = user_repo.create_user({"username": username, "sub": sub, "is_admin": is_admin})

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
            return {
                "id": user.id,
                "username": user.username,
                "is_admin": user.is_admin,
                "created_at": user.created_at,
                "message": "User created successfully. User details will be filled from OIDC during first login.",
            }
        except APIError:
            # Re-raise API errors
            raise
        except Exception as e:
            logging.error("Error creating user: %s", str(e))
            raise APIError(f"Failed to create user: {e!s}") from e

    def list_users(self, session) -> dict[str, Any]:
        """List all users.

        Args:
            session: Database session

        Returns:
            Dict with list of users

        Raises:
            APIError: If an error occurs during processing
        """
        try:
            user_repo = UserRepository(session)
            users = user_repo.get_all_users()

            # Format response
            user_list = {
                "users": [
                    {
                        "id": user.id,
                        "username": user.username,
                        "email": user.email,
                        "is_admin": user.is_admin,
                        "organization": user.organization,
                        "created_at": user.created_at,
                        "last_login": user.last_login,
                        "sub": user.sub,
                        "given_name": user.given_name,
                        "family_name": user.family_name,
                        "name": user.name,
                        "locale": user.locale,
                        "email_verified": user.email_verified,
                    }
                    for user in users
                ]
            }

            return user_list
        except Exception as e:
            logging.error("Error listing users: %s", str(e))
            raise APIError(f"Failed to list users: {e!s}") from e

    def get_user(self, username, session) -> dict[str, Any]:
        """Get detailed user information.

        Args:
            username: Username of the user to get
            session: Database session

        Returns:
            Dict with user info

        Raises:
            NotFoundError: If user is not found
            APIError: If an error occurs during processing
        """
        try:
            user_repo = UserRepository(session)
            user = user_repo.get_by_username(username)

            if not user:
                raise NotFoundError("User not found")

            associations = user.social_auth
            # Format user information
            user_info = {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "organization": user.organization,
                "is_admin": user.is_admin,
                "created_at": user.created_at,
                "sub": user.sub,
                "given_name": user.given_name,
                "family_name": user.family_name,
                "name": user.name,
                "locale": user.locale,
                "email_verified": user.email_verified,
                "last_login": user.last_login,
                "auth_providers": [
                    {
                        "provider": assoc.provider,
                        "provider_user_id": assoc.provider_user_id,
                        "provider_name": assoc.provider_name,
                        "created_at": assoc.created_at,
                        "last_used": assoc.last_used,
                    }
                    for assoc in associations
                ],
            }

            return {"user": user_info}
        except APIError:
            # Re-raise API errors
            raise
        except Exception as e:
            logging.error("Error getting user: %s", str(e))
            raise APIError(f"Failed to get user information: {e!s}") from e

    def verify_user_by_sub(self, sub, session) -> dict[str, Any]:
        """Verify if a user with the given sub exists.

        Args:
            sub: OIDC subject identifier
            session: Database session

        Returns:
            Dict with verification result

        Raises:
            BadRequestError: If sub is missing
            NotFoundError: If user is not found
            APIError: If an error occurs during processing
        """
        try:
            if not sub:
                raise BadRequestError("Missing sub parameter")

            user_repo = UserRepository(session)
            user = user_repo.get_by_sub(sub)

            if not user:
                raise NotFoundError("User not found")

            return {"exists": True, "user_id": user.id, "username": user.username}
        except APIError:
            # Re-raise API errors
            raise
        except Exception as e:
            logging.error("Error verifying user by sub: %s", str(e))
            raise APIError(f"Failed to verify user: {e!s}") from e
