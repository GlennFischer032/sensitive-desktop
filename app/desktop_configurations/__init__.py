"""Desktop configurations module."""
from flask import Blueprint

desktop_config_bp = Blueprint(
    "desktop_configurations", __name__, url_prefix="/desktop-configurations"
)

from app.desktop_configurations import routes  # noqa: F401, E402
