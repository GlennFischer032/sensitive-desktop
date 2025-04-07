from flask import Blueprint

users_bp = Blueprint("users", __name__, url_prefix="/users")
users_api_bp = Blueprint("users_api", __name__, url_prefix="/api/users")

# Import routes to register them with the blueprint
from . import routes  # noqa: F401, E402
from . import api_routes  # noqa: F401, E402
