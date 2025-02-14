from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
from desktop_manager.core.database import init_db
from desktop_manager.config.settings import get_settings
from desktop_manager.config.security import get_security_settings, SecuritySettings
from desktop_manager.api.routes import auth_bp, connections_bp, users_bp
from desktop_manager.api.models.user import User
from desktop_manager.api.models.base import get_db
from desktop_manager.core.guacamole import (
    guacamole_login,
    create_guacamole_user_if_not_exists,
    ensure_admins_group,
    add_user_to_group
)
from desktop_manager.api.middleware.validation import (
    RequestValidationConfig,
    sanitize_headers,
    validate_content_length,
    validate_content_type
)
from werkzeug.security import generate_password_hash, check_password_hash
from http import HTTPStatus

# Add logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_app() -> Flask:
    """Create and configure the Flask application."""
    settings = get_settings()
    security_settings = get_security_settings()
    
    app = Flask(__name__)
    
    # Security configuration
    app.config.update(
        SECRET_KEY=settings.SECRET_KEY,
        SESSION_COOKIE_NAME=security_settings.SESSION_COOKIE_NAME,
        SESSION_COOKIE_SECURE=security_settings.SESSION_COOKIE_SECURE,
        SESSION_COOKIE_HTTPONLY=security_settings.SESSION_COOKIE_HTTPONLY,
        SESSION_COOKIE_SAMESITE=security_settings.SESSION_COOKIE_SAMESITE,
        PERMANENT_SESSION_LIFETIME=security_settings.SESSION_LIFETIME,
        MAX_CONTENT_LENGTH=security_settings.MAX_CONTENT_LENGTH
    )
    
    # Configure CORS with stricter security
    CORS(
        app,
        resources={
            r"/*": {
                "origins": ["http://localhost:8000"] + list(security_settings.CORS_ALLOWED_ORIGINS),
                "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
                "expose_headers": ["Content-Length", "Content-Range"],
                "supports_credentials": True,
                "max_age": 3600,
                "send_wildcard": False
            }
        }
    )
    
    # Initialize database
    init_db()

    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(connections_bp, url_prefix='/api/connections')
    app.register_blueprint(users_bp, url_prefix='/api/users')

    # Global request handlers
    @app.before_request
    def before_request():
        # Validate content length
        if request.content_length and request.content_length > security_settings.MAX_CONTENT_LENGTH:
            return jsonify({
                "error": "Request entity too large",
                "max_size": f"{security_settings.MAX_CONTENT_LENGTH/1024/1024}MB"
            }), HTTPStatus.REQUEST_ENTITY_TOO_LARGE
            
        # Validate content type
        if request.method in ["POST", "PUT", "PATCH"]:
            content_type = request.content_type
            if not content_type:
                return jsonify({
                    "error": "Content-Type header is required"
                }), HTTPStatus.BAD_REQUEST
                
            base_content_type = content_type.split(";")[0].lower()
            if base_content_type not in security_settings.ALLOWED_CONTENT_TYPES:
                return jsonify({
                    "error": "Unsupported content type",
                    "allowed_types": list(security_settings.ALLOWED_CONTENT_TYPES)
                }), HTTPStatus.UNSUPPORTED_MEDIA_TYPE

    @app.after_request
    def after_request(response):
        # Add security headers
        for header, value in security_settings.SECURITY_HEADERS.items():
            response.headers[header] = value
        return response

    # Error handlers
    @app.errorhandler(HTTPStatus.NOT_FOUND)
    def not_found_error(error):
        return jsonify({
            "error": "Not Found",
            "message": "The requested resource was not found"
        }), HTTPStatus.NOT_FOUND

    @app.errorhandler(HTTPStatus.INTERNAL_SERVER_ERROR)
    def internal_error(error):
        logger.error(f"Internal server error: {str(error)}")
        return jsonify({
            "error": "Internal Server Error",
            "message": "An unexpected error occurred"
        }), HTTPStatus.INTERNAL_SERVER_ERROR

    # Initialize admin user
    with app.app_context():
        try:
            initialize_admin_user(app)
        except Exception as e:
            logger.error(f"Error during initialization: {str(e)}")

    @app.route('/api/health')
    def health_check():
        return {"status": "healthy"}, HTTPStatus.OK

    logger.info("=== Starting API Application ===")
    return app

def initialize_admin_user(app):
    """Initialize the admin user with secure password hashing."""
    settings = get_settings()
    security_settings = get_security_settings()
    db = next(get_db())
    
    try:
        # Get admin credentials from config
        admin_username = settings.ADMIN_USERNAME
        admin_password = settings.ADMIN_PASSWORD

        if not admin_username or not admin_password:
            logger.error("ADMIN_USERNAME and ADMIN_PASSWORD must be set in environment variables.")
            return

        # Check if admin user already exists
        existing_admin = db.query(User).filter_by(username=admin_username).first()
        
        if existing_admin:
            logger.info(f"Admin user '{admin_username}' already exists")
            # Update password if it has changed
            if not check_password_hash(existing_admin.password_hash, admin_password):
                existing_admin.password_hash = generate_password_hash(
                    admin_password,
                    method='pbkdf2:sha256:' + str(security_settings.PASSWORD_HASH_ROUNDS)
                )
                db.commit()
                logger.info(f"Updated password for admin user '{admin_username}'")
        else:
            # Create admin user with secure password hash
            admin_user = User(
                username=admin_username,
                password_hash=generate_password_hash(
                    admin_password,
                    method='pbkdf2:sha256:' + str(security_settings.PASSWORD_HASH_ROUNDS)
                ),
                is_admin=True
            )
            db.add(admin_user)
            try:
                db.commit()
                logger.info(f"Admin user '{admin_username}' created successfully")
            except Exception as e:
                logger.error(f"Failed to create admin user: {str(e)}")
                db.rollback()
                return

        # Create admin user in Guacamole with secure configuration
        try:
            token = guacamole_login()
            create_guacamole_user_if_not_exists(token, admin_username, admin_password)
            ensure_admins_group(token)
            add_user_to_group(token, admin_username, 'admins')
            logger.info(f"Admin user '{admin_username}' initialized in Guacamole")
        except Exception as e:
            logger.error(f"Failed to initialize admin user in Guacamole: {str(e)}")
            raise

    except Exception as e:
        logger.error(f"Error initializing admin user: {str(e)}")
        db.rollback()
    finally:
        db.close()

app = create_app() 