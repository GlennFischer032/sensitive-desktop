from flask import Blueprint

users_bp = Blueprint("users", __name__, url_prefix="/users")
users_api_bp = Blueprint("users_api", __name__, url_prefix="/api/users")


from . import (  # noqa: F401, E402
    api_routes,
    routes,
)
