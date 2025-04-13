"""Routes package for desktop-manager-api."""

from routes.connection_routes import connections_bp
from routes.desktop_configuration_routes import desktop_config_bp
from routes.oidc_routes import oidc_bp
from routes.storage_pvc_routes import storage_pvc_bp
from routes.token_routes import token_bp
from routes.user_routes import users_bp


__all__ = [
    "connections_bp",
    "desktop_config_bp",
    "oidc_bp",
    "storage_pvc_bp",
    "token_bp",
    "users_bp",
]
