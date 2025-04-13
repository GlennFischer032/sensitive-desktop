from datetime import datetime
from functools import wraps

from database.core.session import get_db_session
from database.repositories.token import TokenRepository
from database.repositories.user import UserRepository
from flask import current_app, jsonify, request
import jwt


def token_required(f):
    """Decorator to validate JWT token.

    Args:
        f: Function to decorate

    Returns:
        Decorated function
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]  # Remove 'Bearer ' prefix
        if not token:
            return jsonify({"message": "Token is missing!"}), 401
        try:
            # First try to validate as JWT token

            data = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])

            # Check if this is an API token
            token_id = data.get("token_id")
            if token_id:
                current_app.logger.info("Token identified as API token with ID: %s", token_id)
                # This is an API token, check if it's valid
                with get_db_session() as session:
                    token_repo = TokenRepository(session)
                    token = token_repo.get_by_token_id(token_id)
                    if not token:
                        return jsonify({"message": "Token is invalid"}), 401
                    if token.revoked:
                        return jsonify({"message": "Token is revoked"}), 401
                    if token.expires_at < datetime.utcnow():
                        return jsonify({"message": "Token is expired"}), 401

                    token_repo = TokenRepository(session)
                    token_repo.update_last_used(token_id)
                    current_app.logger.info("API token validated for user: %s", token.created_by)

                    user_repo = UserRepository(session)
                    user = user_repo.get_by_username(token.created_by)
                    if not user:
                        return jsonify({"message": "User not found!"}), 401

                    # Detach the user from the session so it can be used after session closes
                    session.expunge(user)
                    request.current_user = user
            else:
                with get_db_session() as session:
                    user_repo = UserRepository(session)
                    user = user_repo.get_by_sub(data["sub"])
                    if not user:
                        return jsonify({"message": "User not found!"}), 401

                    # Detach the user from the session so it can be used after session closes
                    session.expunge(user)
                    request.current_user = user
            # Call the decorated function
            return f(*args, **kwargs)
        except Exception as e:
            current_app.logger.error("Token validation error: %s", str(e))
            return jsonify({"message": "Token is invalid!"}), 401

    return decorated


def admin_required(f):
    """Decorator to check if user is admin.

    Args:
        f: Function to decorate

    Returns:
        Decorated function
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        # Check if current_user is set (token_required decorator must be applied first)
        if not hasattr(request, "current_user"):
            return jsonify({"message": "Authorization required!"}), 401

        # Check if user is admin
        if not request.current_user.is_admin:
            return jsonify({"message": "Admin privilege required!"}), 403

        # Call the decorated function
        return f(*args, **kwargs)

    return decorated
