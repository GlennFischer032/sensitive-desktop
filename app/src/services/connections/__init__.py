from flask import Blueprint

connections_bp = Blueprint("connections", __name__, url_prefix="/connections")
connections_api_bp = Blueprint("connections_api", __name__, url_prefix="/api/connections")

# Import routes to register them with the blueprint
from . import (  # noqa: F401, E402
    api_routes,
    routes,
)
