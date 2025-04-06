"""API Tokens module for desktop-frontend.

This module provides routes for managing API tokens.
"""

from flask import Blueprint

tokens_bp = Blueprint("tokens", __name__, url_prefix="/tokens")

from . import routes  # noqa
