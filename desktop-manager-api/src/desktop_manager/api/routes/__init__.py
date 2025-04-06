"""Routes package for desktop-manager-api."""

from desktop_manager.api.routes.auth_routes import auth_bp
from desktop_manager.api.routes.connection_routes import connections_bp
from desktop_manager.api.routes.desktop_configuration_routes import desktop_config_bp
from desktop_manager.api.routes.oidc_routes import oidc_bp
from desktop_manager.api.routes.storage_pvc_routes import storage_pvc_bp
from desktop_manager.api.routes.token_routes import token_bp
from desktop_manager.api.routes.user_routes import users_bp


__all__ = [
    "auth_bp",
    "connections_bp",
    "desktop_config_bp",
    "oidc_bp",
    "storage_pvc_bp",
    "token_bp",
    "users_bp",
]
