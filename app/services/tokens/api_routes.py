"""API routes for token management.

This module provides API endpoints for managing API tokens, separate from UI routes.
"""

from http import HTTPStatus

from dateutil import parser
from flask import current_app, jsonify, request

from app.clients.factory import client_factory
from app.middleware.auth import admin_required, login_required

from . import tokens_api_bp


def parse_date_safely(date_str):
    """Parse a date string safely, handling various formats.

    Args:
        date_str: A date string in any recognizable format

    Returns:
        datetime object or None if parsing fails
    """
    if not date_str:
        return None

    try:
        parsed_date = parser.parse(date_str)
        if parsed_date.tzinfo:
            return parsed_date.replace(tzinfo=None)
        return parsed_date
    except Exception as e:
        current_app.logger.debug(f"Error parsing date {date_str}: {str(e)}")
        return None


@tokens_api_bp.route("/", methods=["GET"])
@login_required
@admin_required
def list_tokens():
    """Get a list of all API tokens.
    ---
    tags:
      - Tokens API
    responses:
      200:
        description: A list of API tokens
        schema:
          type: object
          properties:
            tokens:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: string
                  name:
                    type: string
                  description:
                    type: string
                  created_at:
                    type: string
                    format: date-time
                  expires_at:
                    type: string
                    format: date-time
                  last_used:
                    type: string
                    format: date-time
                  revoked:
                    type: boolean
                  revoked_at:
                    type: string
                    format: date-time
      403:
        description: Forbidden - User is not an administrator
      500:
        description: Server error
    """
    try:
        current_app.logger.info("API: Fetching tokens list")
        tokens_client = client_factory.get_tokens_client()
        response = tokens_client.list_tokens()

        tokens = response.get("tokens", [])

        # Convert string timestamps to ISO format
        for token in tokens:
            timestamp_fields = ["created_at", "expires_at", "last_used", "revoked_at"]
            for field in timestamp_fields:
                if field in token and token[field]:
                    date_obj = parse_date_safely(token[field])
                    if date_obj:
                        token[field] = date_obj.isoformat()

        return jsonify({"tokens": tokens}), HTTPStatus.OK
    except Exception as e:
        current_app.logger.error(f"API Error fetching tokens: {str(e)}")
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@tokens_api_bp.route("/", methods=["POST"])
@login_required
@admin_required
def create_token():
    """Create a new API token.
    ---
    tags:
      - Tokens API
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - name
          properties:
            name:
              type: string
              description: Name for the new token
            description:
              type: string
              description: Description for the token
            expires_in_days:
              type: integer
              description: Number of days until the token expires
              default: 30
    responses:
      201:
        description: Token created successfully
        schema:
          type: object
          properties:
            token:
              type: object
              properties:
                id:
                  type: string
                name:
                  type: string
                token:
                  type: string
                  description: The actual token value (only returned once upon creation)
                expires_at:
                  type: string
                  format: date-time
      400:
        description: Invalid request data
      500:
        description: Server error
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), HTTPStatus.BAD_REQUEST

        name = data.get("name")
        description = data.get("description")
        expires_in_days = data.get("expires_in_days", 30)

        if not name:
            return jsonify({"error": "Token name is required"}), HTTPStatus.BAD_REQUEST

        current_app.logger.info(f"API: Creating new token with name: {name}")
        tokens_client = client_factory.get_tokens_client()
        response = tokens_client.create_token(
            name=name,
            description=description,
            expires_in_days=expires_in_days,
        )

        # Convert expiration date to ISO format if present
        if response and "expires_at" in response:
            date_obj = parse_date_safely(response["expires_at"])
            if date_obj:
                response["expires_at"] = date_obj.isoformat()

        return jsonify({"token": response}), HTTPStatus.CREATED

    except Exception as e:
        current_app.logger.error(f"API Error creating token: {str(e)}")
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR


@tokens_api_bp.route("/<token_id>", methods=["DELETE"])
@login_required
@admin_required
def revoke_token(token_id):
    """Revoke an API token.
    ---
    tags:
      - Tokens API
    parameters:
      - name: token_id
        in: path
        type: string
        required: true
        description: ID of the token to revoke
    responses:
      200:
        description: Token revoked successfully
        schema:
          type: object
          properties:
            message:
              type: string
      404:
        description: Token not found
      500:
        description: Server error
    """
    try:
        current_app.logger.info(f"API: Revoking token with ID: {token_id}")
        tokens_client = client_factory.get_tokens_client()
        tokens_client.revoke_token(token_id)

        return jsonify({"message": "Token revoked successfully"}), HTTPStatus.OK

    except Exception as e:
        current_app.logger.error(f"API Error revoking token: {str(e)}")
        return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR
