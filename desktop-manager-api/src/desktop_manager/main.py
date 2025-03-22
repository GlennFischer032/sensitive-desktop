from http import HTTPStatus
import logging

from flask import Flask, jsonify
from flask_cors import CORS
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from desktop_manager.api.models.user import User
from desktop_manager.api.routes import auth_bp, connections_bp, oidc_bp, users_bp
from desktop_manager.clients.factory import client_factory
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
            # Use DatabaseClient to test database connectivity
            db_client = client_factory.get_database_client()
            db_client.execute_query("SELECT 1")
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
        db_client = client_factory.get_database_client()
        try:
            # Check if admin user exists
            query = "SELECT * FROM users WHERE username = :username"
            admins, count = db_client.execute_query(query, {"username": settings.ADMIN_USERNAME})

            if count == 0:
                # Create admin user if not exists
                insert_query = """
                INSERT INTO users (username, email, password_hash, is_admin, created_at)
                VALUES (:username, :email, :password_hash, :is_admin, :created_at)
                """

                from datetime import datetime

                db_client.execute_query(
                    insert_query,
                    {
                        "username": settings.ADMIN_USERNAME,
                        "email": "admin@example.com",
                        "password_hash": generate_password_hash(settings.ADMIN_PASSWORD),
                        "is_admin": True,
                        "created_at": datetime.utcnow(),
                    },
                )
                logger.info("Admin user created")
            else:
                logger.info("Admin user already exists")

            # Initialize admin in Guacamole
            guacamole_client = client_factory.get_guacamole_client()
            token = guacamole_client.login()
            guacamole_client.create_user_if_not_exists(
                token, settings.ADMIN_USERNAME, settings.ADMIN_PASSWORD
            )
            guacamole_client.ensure_group(token, "admins")
            guacamole_client.ensure_group(token, "all_users")
            guacamole_client.add_user_to_group(token, settings.ADMIN_USERNAME, "admins")
            logger.info("Admin user initialized in Guacamole")

        except Exception as e:
            logger.error("Error initializing admin user: %s", str(e))
            raise

    logger.info("=== Starting API Application ===")
    return app


app = create_app()
