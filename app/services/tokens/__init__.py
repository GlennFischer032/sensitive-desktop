"""API Tokens module for desktop-frontend.

This module provides routes for managing API tokens.
"""

from flask import Blueprint

tokens_bp = Blueprint("tokens", __name__, url_prefix="/tokens")
tokens_api_bp = Blueprint("tokens_api", __name__, url_prefix="/api/tokens")

# Import routes to register them with the blueprint
from . import routes  # noqa: F401, E402
from . import api_routes  # noqa: F401, E402
