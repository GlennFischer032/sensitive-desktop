from desktop_manager.api.routes.auth_routes import auth_bp
from desktop_manager.api.routes.connection_routes import connections_bp
from desktop_manager.api.routes.oidc_routes import oidc_bp
from desktop_manager.api.routes.user_routes import users_bp


__all__ = ["auth_bp", "connections_bp", "oidc_bp", "users_bp"]
