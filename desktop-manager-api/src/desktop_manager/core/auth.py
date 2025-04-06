from datetime import datetime
from functools import wraps

from flask import current_app, jsonify, request
import jwt
import requests

from desktop_manager.api.models.user import User
from desktop_manager.clients.factory import client_factory


def token_required(f):
    """Decorator to validate JWT token.

    Args:
        f: Function to decorate

    Returns:
        Decorated function
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Get token from Authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header:
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]  # Remove 'Bearer ' prefix
        if not token:
            return jsonify({"message": "Token is missing!"}), 401
        try:
            # First try to validate as JWT token
            try:
                data = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])

                # Check if this is an API token
                token_id = data.get("token_id")
                if token_id:
                    current_app.logger.info("Token identified as API token with ID: %s", token_id)
                    # This is an API token, check if it's valid
                    db_client = client_factory.get_database_client()
                    query = """
                    SELECT * FROM api_tokens
                    WHERE token_id = :token_id AND revoked = FALSE
                    AND expires_at > NOW()
                    """
                    tokens, count = db_client.execute_query(query, {"token_id": token_id})

                    if count == 0:
                        current_app.logger.warning(
                            "API token not found, revoked, or expired: %s", token_id
                        )
                        return jsonify({"message": "Token is invalid or revoked!"}), 401

                    # Update last_used timestamp
                    update_query = """
                    UPDATE api_tokens
                    SET last_used = NOW()
                    WHERE token_id = :token_id
                    """
                    db_client.execute_query(update_query, {"token_id": token_id})

                    # Get user info for the token creator
                    username = tokens[0]["created_by"]
                    query = "SELECT * FROM users WHERE username = :username"
                    users, count = db_client.execute_query(query, {"username": username})

                    if count == 0:
                        current_app.logger.error("User not found for API token: %s", username)
                        return jsonify({"message": "User not found!"}), 401

                    current_user = users[0]
                    current_app.logger.info(
                        "API token validated for user: %s", current_user["username"]
                    )
                else:
                    # Regular user token
                    db_client = client_factory.get_database_client()
                    query = "SELECT * FROM users WHERE id = :user_id"
                    users, count = db_client.execute_query(query, {"user_id": int(data["sub"])})

                    if count == 0:
                        return jsonify({"message": "User not found!"}), 401

                    current_user = users[0]
            except jwt.InvalidTokenError:
                # If JWT validation fails, try OIDC token validation
                current_app.logger.info("JWT validation failed, trying OIDC token validation")
                try:
                    # Call userinfo endpoint to get user info
                    userinfo_response = requests.get(
                        "https://login.e-infra.cz/oidc/userinfo",
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=10,
                    )
                    userinfo_response.raise_for_status()
                    userinfo = userinfo_response.json()
                    current_app.logger.info("Userinfo response: %s", userinfo)

                    # Get sub from userinfo
                    sub = userinfo.get("sub")
                    if not sub:
                        current_app.logger.error("No sub in userinfo response")
                        raise jwt.InvalidTokenError("No sub in userinfo")
                    current_app.logger.info("Found sub in userinfo: %s", sub)

                    # Find user by sub
                    db_client = client_factory.get_database_client()
                    query = "SELECT * FROM users WHERE sub = :sub"
                    users, count = db_client.execute_query(query, {"sub": sub})

                    if count == 0:
                        return jsonify({"message": "User not found!"}), 401

                    current_user = users[0]
                    current_app.logger.info("Found user: %s", current_user["username"])

                    # Update user information if needed
                    update_fields = {}
                    if userinfo.get("email") and current_user["email"] != userinfo.get("email"):
                        update_fields["email"] = userinfo.get("email")

                    if userinfo.get("given_name") and current_user.get(
                        "given_name"
                    ) != userinfo.get("given_name"):
                        update_fields["given_name"] = userinfo.get("given_name")

                    if userinfo.get("family_name") and current_user.get(
                        "family_name"
                    ) != userinfo.get("family_name"):
                        update_fields["family_name"] = userinfo.get("family_name")

                    if userinfo.get("organization") and current_user.get(
                        "organization"
                    ) != userinfo.get("organization"):
                        update_fields["organization"] = userinfo.get("organization")

                    if userinfo.get("preferred_username") and current_user[
                        "username"
                    ] != userinfo.get("preferred_username"):
                        update_fields["username"] = userinfo.get("preferred_username")

                    if update_fields:
                        # Add last_login to update
                        update_fields["last_login"] = datetime.utcnow()

                        # Create SET clauses
                        set_clauses = ", ".join([f"{field} = :{field}" for field in update_fields])

                        # Add user_id for WHERE clause
                        update_fields["user_id"] = current_user["id"]

                        # Execute update query
                        update_query = f"UPDATE users SET {set_clauses} WHERE id = :user_id"  # noqa: S608
                        db_client.execute_query(update_query, update_fields)

                        current_app.logger.info("Updated user information")

                        # Refresh user data
                        users, _ = db_client.execute_query(query, {"sub": sub})
                        current_user = users[0]
                except Exception as e:
                    current_app.logger.error("OIDC token validation failed: %s", str(e))
                    return jsonify({"message": "Token is invalid!"}), 401

            # Add current_user to request
            request.current_user = User(**current_user)
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
