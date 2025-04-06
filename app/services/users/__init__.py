from flask import Blueprint

users_bp = Blueprint("users", __name__, url_prefix="/users")

# Import routes to register them with the blueprint
from . import routes  # noqa: F401, E402
