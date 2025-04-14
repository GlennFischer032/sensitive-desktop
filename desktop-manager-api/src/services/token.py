from datetime import datetime
import logging
from typing import Any

from database.repositories.token import TokenRepository
from database.repositories.user import UserRepository
from flask import current_app
import jwt
from pydantic import ValidationError
from schemas.token import Token, TokenCreate, TokenResponse
from services.connections import APIError, BadRequestError, NotFoundError


class TokenService:
    """Service for managing API tokens."""

    def create_token(self, data, current_user, session) -> dict[str, Any]:
        """Create a new API token.

        Args:
            data: Token data including name, description, and expires_in_days
            current_user: Current authenticated user
            session: Database session

        Returns:
            Dictionary with created token details

        Raises:
            BadRequestError: If request data is invalid
            APIError: If an error occurs during processing
        """
        try:
            if not data:
                raise BadRequestError("Missing request data")

            try:
                token_data = TokenCreate(**data)
            except ValidationError as e:
                raise BadRequestError(str(e)) from e

            token_repo = TokenRepository(session)
            token = token_repo.create_token(
                name=token_data.name,
                description=token_data.description,
                expires_in_days=token_data.expires_in_days,
                created_by=current_user.username,
            )

            # Generate JWT token with custom expiration
            payload = {
                "sub": f"token:{token.token_id}",  # Prefix to distinguish from user IDs
                "name": current_user.username,
                "token_id": token.token_id,
                "iat": datetime.utcnow(),
                "exp": token.expires_at,
                "admin": current_user.is_admin,  # Preserve admin privileges
            }

            token_jwt = jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")

            # Create response object
            response = TokenResponse(
                token=token_jwt,
                token_id=token.token_id,
                name=token.name,
                expires_at=token.expires_at,
                created_by=current_user.username,
            )

            return response.model_dump()
        except APIError:
            # Re-raise API errors
            raise
        except Exception as e:
            error_message = f"Failed to create API token: {e!s}"
            logging.error(error_message)
            raise APIError(error_message) from e

    def list_tokens(self, current_user, session) -> dict[str, Any]:
        """List all tokens for the current admin user.

        Args:
            current_user: Current authenticated user
            session: Database session

        Returns:
            Dictionary with list of tokens

        Raises:
            APIError: If an error occurs during processing
        """
        try:
            token_repo = TokenRepository(session)
            tokens = token_repo.get_tokens_for_user(current_user.username)

            # Convert to Pydantic models for validation and to format dates correctly
            token_list = [Token.model_validate(token) for token in tokens]

            return {"tokens": [t.model_dump() for t in token_list]}
        except Exception as e:
            error_message = f"Failed to list API tokens: {e!s}"
            logging.error(error_message)
            raise APIError(error_message) from e

    def revoke_token(self, token_id, session) -> dict[str, Any]:
        """Revoke (delete) a token.

        Args:
            token_id: The unique ID of the token to revoke
            session: Database session

        Returns:
            Dictionary with success message

        Raises:
            APIError: If an error occurs during processing
        """
        try:
            token_repo = TokenRepository(session)
            # Check if token exists
            token = token_repo.get_by_id(token_id)
            if not token:
                raise NotFoundError(f"Token with ID {token_id} not found")

            token_repo.revoke_token(token_id)

            return {"message": "Token successfully revoked"}
        except APIError:
            # Re-raise API errors
            raise
        except Exception as e:
            error_message = f"Failed to revoke API token: {e!s}"
            logging.error(error_message)
            raise APIError(error_message) from e

    def api_login(self, token, session) -> dict[str, Any]:
        """API login endpoint.

        This endpoint allows API clients send a JWT and recieve user data.
        """
        data = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
        token_id = data.get("token_id")
        if not token_id:
            raise BadRequestError("Token is invalid")

        token_repo = TokenRepository(session)
        token = token_repo.get_by_token_id(token_id)
        if not token:
            raise NotFoundError(f"Token with ID {token_id} not found")

        if token.revoked:
            raise BadRequestError("Token is revoked")

        if token.expires_at < datetime.utcnow():
            raise BadRequestError("Token is expired")

        user_repo = UserRepository(session)
        user = user_repo.get_by_username(data.get("name"))
        if not user:
            raise NotFoundError(f"User with username {data.get('name')} not found")

        user_data = {
            "username": user.username,
            "is_admin": user.is_admin,
            "email": user.email,
        }
        return user_data
