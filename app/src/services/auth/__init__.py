from flask import Blueprint

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")
auth_api_bp = Blueprint("auth_api", __name__, url_prefix="/api/auth")

# Import routes to register them with the blueprint
from . import (  # noqa: F401, E402
    api_routes,
    routes,
)
