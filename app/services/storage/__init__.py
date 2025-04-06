from flask import Blueprint

storage_bp = Blueprint("storage", __name__, url_prefix="/storage")

from . import routes  # noqa
