from flask import Blueprint

storage_bp = Blueprint("storage", __name__, url_prefix="/storage")
storage_api_bp = Blueprint("storage_api", __name__, url_prefix="/api/storage")

from . import (  # noqa: F401, E402
    api_routes,
    routes,
)
