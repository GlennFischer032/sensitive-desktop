from datetime import datetime
from http import HTTPStatus
import logging

from flask import Flask, jsonify
from flask_cors import CORS
from sqlalchemy import text

from desktop_manager.api.routes import (
    connections_bp,
    desktop_config_bp,
    oidc_bp,
    storage_pvc_bp,
    token_bp,
    users_bp,
)
from desktop_manager.clients.factory import client_factory
from desktop_manager.config.settings import get_settings
from desktop_manager.database.core.session import get_db_session, initialize_db
from desktop_manager.database.repositories.user import UserRepository


# Add logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)

    # Load configuration
    settings = get_settings()

    app.config.update(
        {
            "SECRET_KEY": settings.SECRET_KEY,
            "SOCIAL_AUTH_OIDC_PROVIDER_URL": settings.OIDC_PROVIDER_URL,
            "SOCIAL_AUTH_OIDC_CLIENT_ID": settings.OIDC_CLIENT_ID,
            "SOCIAL_AUTH_OIDC_CLIENT_SECRET": settings.OIDC_CLIENT_SECRET,
            "SOCIAL_AUTH_OIDC_CALLBACK_URL": settings.OIDC_BACKEND_REDIRECT_URI,
            "SOCIAL_AUTH_LOGIN_REDIRECT_URL": settings.FRONTEND_URL,  # Frontend URL for redirects
            "SOCIAL_AUTH_LOGIN_ERROR_URL": f"{settings.FRONTEND_URL}/login",  # Frontend login URL for errors
            "SOCIAL_AUTH_OIDC_FRONTEND_REDIRECT_URI": settings.OIDC_REDIRECT_URI,  # Use the full OIDC redirect URI
        }
    )

    # Initialize CORS
    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": settings.CORS_ALLOWED_ORIGINS.split(","),
                "supports_credentials": True,
            }
        },
    )

    # Initialize database
    # init_db()

    # Health check endpoint
    @app.route("/api/health", methods=["GET"])
    def health_check():
        """Health check endpoint for the API."""
        try:
            # Use DatabaseClient to test database connectivity
            with get_db_session() as session:
                session.execute(text("SELECT 1"))
            return (
                jsonify(
                    {
                        "status": "healthy",
                        "message": "API is running and database is connected",
                    }
                ),
                HTTPStatus.OK,
            )
        except Exception as e:
            logger.error("Health check failed: %s", str(e))
            return (
                jsonify({"status": "unhealthy", "message": str(e)}),
                HTTPStatus.SERVICE_UNAVAILABLE,
            )

    # Register blueprints
    app.register_blueprint(connections_bp, url_prefix="/api/connections")
    app.register_blueprint(desktop_config_bp, url_prefix="/api/desktop-config")
    app.register_blueprint(users_bp, url_prefix="/api/users")
    app.register_blueprint(storage_pvc_bp, url_prefix="/api/storage-pvcs")
    app.register_blueprint(oidc_bp, url_prefix="/api")
    app.register_blueprint(token_bp, url_prefix="")  # Token routes already include /api prefix

    # Initialize admin user
    with app.app_context():
        # Initialize database tables
        initialize_db()

        with get_db_session() as session:
            # First, check if admin exists via OIDC sub (new method)
            user_repo = UserRepository(session)
            admin = user_repo.get_by_sub(settings.ADMIN_OIDC_SUB)
            if not admin:
                # Generate a username from the sub
                admin_username = f"admin-{settings.ADMIN_OIDC_SUB.split('@')[0][:8]}"
                user_repo.create_user(
                    {
                        "username": admin_username,
                        "email": "admin@example.com",
                        "sub": settings.ADMIN_OIDC_SUB,
                        "is_admin": True,
                        "created_at": datetime.utcnow(),
                    },
                )

                user_repo.create_social_auth(
                    {
                        "sub": settings.ADMIN_OIDC_SUB,
                        "provider": "oidc",
                        "provider_user_id": settings.ADMIN_OIDC_SUB,
                        "provider_name": "e-infra",
                        "created_at": datetime.utcnow(),
                    },
                )

                logger.info("Admin user created with OIDC sub: %s", settings.ADMIN_OIDC_SUB)
            else:
                logger.info("Admin user already exists with OIDC sub: %s", settings.ADMIN_OIDC_SUB)

            # Initialize admin in Guacamole
            guacamole_client = client_factory.get_guacamole_client()
            token = guacamole_client.login()

            # For JSON authentication, we'll create the user without password
            # This is supported since the admin will use OIDC authentication
            if admin.username:
                # Create Guacamole user without password for JSON auth
                guacamole_client.create_user_if_not_exists(
                    token=token,
                    username=admin.username,
                    password="",  # Empty password for JSON auth
                    attributes={"guac_full_name": "Admin User", "guac_organization": "e-INFRA"},
                )
                guacamole_client.ensure_group(token, "admins")
                guacamole_client.ensure_group(token, "all_users")
                guacamole_client.add_user_to_group(token, admin.username, "admins")
            else:
                logger.warning("Could not initialize admin user in Guacamole: no username available")

    logger.info("=== Starting API Application ===")
    return app


app = create_app()
