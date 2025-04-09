"""API Tokens module for desktop-frontend.

This module provides routes for managing API tokens.
"""

from flask import Blueprint

tokens_bp = Blueprint("tokens", __name__, url_prefix="/tokens")
tokens_api_bp = Blueprint("tokens_api", __name__, url_prefix="/api/tokens")

from . import (  # noqa: F401, E402
    api_routes,
    routes,
)
