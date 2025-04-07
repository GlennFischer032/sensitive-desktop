"""API routes for authentication.

This module provides API endpoints for authentication operations, separate from UI routes.
"""

import logging
from http import HTTPStatus

from flask import jsonify, session


from . import auth_api_bp

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


@auth_api_bp.route("/status", methods=["GET"])
def auth_status():
    """Get the current authentication status.
    ---
    tags:
      - Auth API
    responses:
      200:
        description: Current authentication status
        schema:
          type: object
          properties:
            authenticated:
              type: boolean
            user:
              type: object
              properties:
                username:
                  type: string
                is_admin:
                  type: boolean
                email:
                  type: string
    """
    authenticated = session.get("logged_in", False) and "token" in session

    if authenticated:
        user_data = {
            "username": session.get("username"),
            "is_admin": session.get("is_admin", False),
            "email": session.get("email"),
        }
        return jsonify({"authenticated": True, "user": user_data}), HTTPStatus.OK

    return jsonify({"authenticated": False}), HTTPStatus.OK
