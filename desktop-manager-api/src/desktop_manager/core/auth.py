from datetime import datetime
from functools import wraps

from flask import current_app, jsonify, request
import jwt
import requests

from desktop_manager.api.models.base import get_db
from desktop_manager.api.models.user import User
from desktop_manager.clients.guacamole import (
    add_user_to_group,
    create_guacamole_user,
    ensure_all_users_group,
    guacamole_login,
)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # JWT is passed in the request header
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]  # Remove 'Bearer ' prefix
        if not token:
            return jsonify({"message": "Token is missing!"}), 401
        try:
            # First try to validate as JWT token
            try:
                data = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
                db_session = next(get_db())
                current_user = db_session.query(User).filter(User.id == data["user_id"]).first()
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
                    db_session = next(get_db())
                    current_user = db_session.query(User).filter(User.sub == sub).first()
                    if current_user:
                        current_app.logger.info("Found user: %s", current_user.username)

                        # Update user information if needed
                        updated = False
                        if userinfo.get("email") and current_user.email != userinfo.get("email"):
                            current_user.email = userinfo.get("email")
                            updated = True

                        if userinfo.get("given_name") and current_user.given_name != userinfo.get(
                            "given_name"
                        ):
                            current_user.given_name = userinfo.get("given_name")
                            updated = True

                        if userinfo.get("family_name") and current_user.family_name != userinfo.get(
                            "family_name"
                        ):
                            current_user.family_name = userinfo.get("family_name")
                            updated = True

                        if userinfo.get(
                            "organization"
                        ) and current_user.organization != userinfo.get("organization"):
                            current_user.organization = userinfo.get("organization")
                            updated = True

                        if userinfo.get(
                            "preferred_username"
                        ) and current_user.username != userinfo.get("preferred_username"):
                            current_user.username = userinfo.get("preferred_username")
                            updated = True

                        if updated:
                            current_user.last_login = datetime.utcnow()
                            db_session.commit()
                            current_app.logger.info(
                                "Updated user information for: %s", current_user.username
                            )

                            # Try to update Guacamole user as well
                            try:
                                # Prepare Guacamole attributes
                                guacamole_attributes = {
                                    "guac-full-name": f"{current_user.given_name or ''} {current_user.family_name or ''}".strip()
                                    or current_user.username,
                                    "guac-email-address": current_user.email,
                                    "guac-organization": current_user.organization or "",
                                }

                                # Update user in Guacamole
                                from desktop_manager.core.guacamole import (
                                    update_guacamole_user,
                                )

                                update_guacamole_user(
                                    token, current_user.username, guacamole_attributes
                                )
                                current_app.logger.info(
                                    "Updated user %s in Guacamole", current_user.username
                                )
                            except Exception as e:
                                current_app.logger.error(
                                    "Failed to update user in Guacamole: %s", str(e)
                                )
                                # Continue with authentication even if Guacamole update fails
                    else:
                        current_app.logger.error("No user found for sub: %s", sub)
                except requests.exceptions.RequestException as e:
                    current_app.logger.error("Failed to get userinfo: %s", str(e))
                    raise jwt.InvalidTokenError("Failed to get userinfo") from e
                except Exception as e:
                    current_app.logger.error("Failed to validate OIDC token: %s", str(e))
                    raise jwt.InvalidTokenError("Invalid OIDC token") from e

            if not current_user:
                return jsonify({"message": "User not found!"}), 401

            # Attach user to request context
            request.current_user = current_user
            return f(*args, **kwargs)
        except Exception as e:
            current_app.logger.error("Token validation error: %s", str(e))
            return (
                jsonify({"message": "Token validation failed!", "details": str(e)}),
                401,
            )

    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        current_user = getattr(request, "current_user", None)
        if not current_user or not current_user.is_admin:
            return jsonify({"message": "Admin privilege required!"}), 403
        return f(*args, **kwargs)

    return decorated
