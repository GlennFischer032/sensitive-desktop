"""Routes for API Token management.

This module provides routes for creating, viewing, and managing API tokens.
"""

import logging
from datetime import datetime
from urllib.parse import unquote

from dateutil import parser
from flask import flash, render_template, request

from app.clients.factory import client_factory
from app.middleware.auth import admin_required, login_required
from app.services.tokens import tokens_bp

logger = logging.getLogger(__name__)


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
        logger.debug(f"Error parsing date {date_str}: {str(e)}")
        return None


@tokens_bp.route("/", methods=["GET"])
@login_required
@admin_required
def view_tokens():
    """View API tokens page.
    This endpoint displays the API tokens page, which shows all tokens
    created by the current user and allows creating new tokens.
    ---
    tags:
      - Tokens
    responses:
      200:
        description: API tokens page displayed successfully
      500:
        description: Error retrieving API tokens
    """
    try:
        tokens = _fetch_tokens()
        new_token = _get_new_token_from_args()
        now = datetime.utcnow()

        return render_template("tokens.html", tokens=tokens, now=now, new_token=new_token)
    except Exception as e:
        logger.error(f"Error retrieving API tokens: {str(e)}")
        flash(f"Error retrieving API tokens: {str(e)}", "error")
        return render_template("tokens.html", tokens=[], now=datetime.utcnow())


def _fetch_tokens():
    """Fetch tokens and convert timestamps to datetime objects."""
    tokens_client = client_factory.get_tokens_client()
    response = tokens_client.list_tokens()

    tokens = response.get("tokens", [])

    # Convert string timestamps to datetime objects for template
    for token in tokens:
        _convert_token_timestamps(token)

    return tokens


def _convert_token_timestamps(token):
    """Convert token timestamp strings to datetime objects."""
    timestamp_fields = ["created_at", "expires_at", "last_used", "revoked_at"]

    for field in timestamp_fields:
        if field in token and token[field]:
            token[field] = parse_date_safely(token[field])


def _get_new_token_from_args():
    """Get new token from query parameters if present."""
    new_token = None
    if request.args.get("new_token"):
        try:
            import json
            from urllib.parse import unquote

            new_token_data = request.args.get("new_token")
            if isinstance(new_token_data, str):
                try:
                    new_token = json.loads(unquote(new_token_data))
                except json.JSONDecodeError:
                    new_token = _parse_key_value_token_data(new_token_data)

            if new_token and "expires_at" in new_token:
                new_token["expires_at"] = parse_date_safely(new_token["expires_at"])
        except Exception as e:
            logger.error(f"Error parsing new token data: {str(e)}")
            new_token = None

    return new_token


def _parse_key_value_token_data(new_token_data):
    """Parse URL-encoded key-value pairs into a dictionary."""
    new_token = {}
    parts = unquote(new_token_data).strip("{}").split(",")
    for part in parts:
        if ":" in part:
            key, value = part.split(":", 1)
            new_token[key.strip().strip("'\"")] = value.strip().strip("'\"")
    return new_token
