from flask import Blueprint

storage_bp = Blueprint("storage", __name__, url_prefix="/storage")
storage_api_bp = Blueprint("storage_api", __name__, url_prefix="/api/storage")

from . import routes  # noqa: F401, E402
from . import api_routes  # noqa: F401, E402
