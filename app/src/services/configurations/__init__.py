from flask import Blueprint

configurations_bp = Blueprint("configurations", __name__, url_prefix="/configurations")
configurations_api_bp = Blueprint("configurations_api", __name__, url_prefix="/api/configurations")

# Register routes with the blueprint
from . import (  # noqa: F401, E402
    api_routes,
    routes,
)
