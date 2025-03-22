from http import HTTPStatus
import logging

from flask import Flask, jsonify
from flask_cors import CORS
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from desktop_manager.api.models.base import get_db
from desktop_manager.api.models.user import User
from desktop_manager.api.routes import auth_bp, connections_bp, oidc_bp, users_bp
from desktop_manager.clients.guacamole import (
    add_user_to_group,
    create_guacamole_user_if_not_exists,
    ensure_admins_group,
    ensure_all_users_group,
    guacamole_login,
)
from desktop_manager.config.settings import get_settings
from desktop_manager.core.database import init_db


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
    init_db()

    # Health check endpoint
    @app.route("/api/health", methods=["GET"])
    def health_check():
        """Health check endpoint for the API."""
        try:
            # Get a database session to test database connectivity
            db_session = next(get_db())
            db_session.execute(text("SELECT 1"))
            db_session.close()
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
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(connections_bp, url_prefix="/api/connections")
    app.register_blueprint(users_bp, url_prefix="/api/users")
    app.register_blueprint(oidc_bp, url_prefix="/api")  # OIDC routes

    # Initialize admin user
    with app.app_context():
        db_session = next(get_db())
        try:
            admin = db_session.query(User).filter(User.username == settings.ADMIN_USERNAME).first()
            if not admin:
                admin = User(
                    username=settings.ADMIN_USERNAME,
                    email="admin@example.com",
                    password_hash=generate_password_hash(settings.ADMIN_PASSWORD),
                    is_admin=True,
                )
                db_session.add(admin)
                db_session.commit()
                logger.info("Admin user created")
            else:
                logger.info("Admin user already exists")

            # Initialize admin in Guacamole
            token = guacamole_login()
            create_guacamole_user_if_not_exists(
                token, settings.ADMIN_USERNAME, settings.ADMIN_PASSWORD
            )
            ensure_admins_group(token)
            ensure_all_users_group(token)
            add_user_to_group(token, settings.ADMIN_USERNAME, "admins")
            logger.info("Admin user initialized in Guacamole")

        except Exception as e:
            logger.error("Error initializing admin user: %s", str(e))
            raise
        finally:
            db_session.close()

    logger.info("=== Starting API Application ===")
    return app


app = create_app()
