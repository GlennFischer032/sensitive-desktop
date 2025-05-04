from http import HTTPStatus
import logging
import time

from config.settings import get_settings
from database.core.session import get_db_session, initialize_db
from flask import Flask, jsonify
from flask_cors import CORS
from routes import (
    connections_bp,
    desktop_config_bp,
    oidc_bp,
    storage_pvc_bp,
    token_bp,
    users_bp,
)
from services.user import UserService
from sqlalchemy import text


settings = get_settings()

# Add logging configuration
logging.basicConfig(level=settings.LOG_LEVEL)
logger = logging.getLogger(__name__)


def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)

    # Load configuration

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
    initialize_db()

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
    with app.app_context(), get_db_session() as session:
        for attempt in range(10):
            try:
                user_service = UserService()
                user_service.init_admin_user(session)
                logger.debug("Admin user initialized successfully")
                break
            except Exception as e:
                logger.error("Error initializing admin user: %s (attempt %d)", str(e), attempt + 1)
                if attempt < 9:
                    logger.debug("Retrying in 5 seconds...")
                    time.sleep(5)
                else:
                    logger.error("Failed to initialize admin user after 10 attempts")
                    raise e
    return app


app = create_app()
