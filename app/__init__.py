import logging
import secrets
from datetime import datetime
from http import HTTPStatus

import redis
import requests
from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from flask_cors import CORS
from flask_session import Session

from app.auth import auth_bp
from app.configurations import configurations_bp
from app.connections import connections_bp
from app.storage import storage_bp
from app.tokens import tokens_bp
from app.users import users_bp
from config.config import Config
from middleware.security import init_security, rate_limiter
from utils.decorators import login_required


def init_session(app: Flask):
    """Initialize the session for the application."""
    # Initialize session
    if app.config.get("SESSION_TYPE") != "null":
        # Only use Redis session when not in test mode with null session
        redis_client = redis.from_url(app.config["SESSION_REDIS"])
        app.config["SESSION_REDIS"] = redis_client
        Session(app)
    else:
        # For testing, we'll use the default Flask session (signed cookies)
        app.logger.info("Using default Flask session interface for testing")

    app.config["SESSION_REFRESH_EACH_REQUEST"] = True


def init_cors(app: Flask):
    CORS(
        app,
        resources={
            r"/*": {
                "origins": app.config.get("CORS_ALLOWED_ORIGINS", [app.config["API_URL"]]),
                "supports_credentials": app.config.get("CORS_SUPPORTS_CREDENTIALS", True),
                "expose_headers": app.config.get("CORS_EXPOSE_HEADERS", ["Content-Range", "X-Total-Count"]),
                "allow_headers": app.config.get(
                    "CORS_ALLOWED_HEADERS",
                    [
                        "Content-Type",
                        "Authorization",
                        "X-Requested-With",
                        "Accept",
                        "Origin",
                    ],
                ),
                "methods": app.config.get("CORS_ALLOWED_METHODS", ["GET", "POST", "PUT", "DELETE", "OPTIONS"]),
                "max_age": app.config.get("CORS_MAX_AGE", 3600),
            }
        },
    )


def create_app(config_class=Config):  # noqa: C901, PLR0915
    """Create and configure the Flask application."""
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize security features
    init_security(app)

    init_session(app)

    init_cors(app)

    # Request validation middleware
    @app.before_request
    def validate_request():
        # Skip validation for static files and health check
        if request.endpoint in ["static", "health_check", "test_api_connection"]:
            return None

        # Validate content type for POST/PUT requests that expect JSON
        if request.method in ["POST", "PUT"]:
            # List of endpoints that accept form data
            form_endpoints = [
                "auth.login",
                "users.add_user",
                "users.delete_user",
                "connections.add_connection",
                "connections.delete_connection",
                "tokens.create_token",
                "tokens.revoke_token",
            ]

            # Only enforce JSON content type for non-form endpoints
            if request.endpoint not in form_endpoints:
                content_type = request.headers.get("Content-Type", "")
                if not content_type.startswith("application/json"):
                    return {
                        "error": "Invalid Content-Type",
                        "message": "Content-Type must be application/json",
                    }, HTTPStatus.BAD_REQUEST

        # Validate content length
        max_content_length = app.config.get("MAX_CONTENT_LENGTH", 10 * 1024 * 1024)  # 10MB default
        if (
            max_content_length is not None
            and request.content_length is not None
            and request.content_length > max_content_length
        ):
            return {
                "error": "Request too large",
                "message": f"Request exceeds maximum size of {max_content_length / 1024 / 1024}MB",
            }, HTTPStatus.REQUEST_ENTITY_TOO_LARGE

        # Generate CSP nonce for inline scripts
        if not hasattr(request, "csp_nonce"):
            request.csp_nonce = secrets.token_hex(16)

    # Security headers middleware
    @app.after_request
    def add_security_headers(response):
        # Add CSP nonce if exists
        if hasattr(request, "csp_nonce"):
            csp = response.headers.get("Content-Security-Policy", "")
            if csp:
                csp = csp.replace(
                    "script-src 'self'",
                    f"script-src 'self' 'nonce-{request.csp_nonce}'",
                )
                response.headers["Content-Security-Policy"] = csp

        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        return response

    # Apply global rate limiting
    @app.before_request
    def check_rate_limit():
        # Skip rate limiting for specific endpoints if needed
        if request.endpoint in ["static", "health_check", "test_api_connection"]:
            return None

        # Get client IP
        client_ip = request.remote_addr

        # Use default limits from config
        default_limits = {
            "1s": (app.config["RATE_LIMIT_DEFAULT_SECOND"], 1),
            "1m": (app.config["RATE_LIMIT_DEFAULT_MINUTE"], 60),
            "1h": (app.config["RATE_LIMIT_DEFAULT_HOUR"], 3600),
        }

        # Check rate limit
        is_limited, retry_after = rate_limiter.is_rate_limited(client_ip, default_limits)

        if is_limited:
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return {
                    "error": "Too many requests",
                    "message": f"Please try again in {retry_after} seconds",
                }, HTTPStatus.TOO_MANY_REQUESTS
            return (
                render_template(
                    "errors/429.html",
                    error={
                        "message": "Too many requests. Please try again later.",
                        "retry_after": retry_after,
                    },
                ),
                HTTPStatus.TOO_MANY_REQUESTS,
            )

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(connections_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(configurations_bp)
    app.register_blueprint(storage_bp)
    app.register_blueprint(tokens_bp)

    # Error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return (
            render_template(
                "errors/404.html",
                error={"message": getattr(error, "description", None)},
            ),
            404,
        )

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Server Error: {str(error)}")
        return (
            render_template(
                "errors/500.html",
                error={
                    "message": "An unexpected error has occurred.",
                    "details": str(error) if app.debug else None,
                },
            ),
            500,
        )

    @app.errorhandler(429)
    def ratelimit_error(error):
        retry_after = None
        if hasattr(error, "description") and isinstance(error.description, dict):
            retry_after = error.description.get("retry_after")

        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return {
                "error": "Too many requests",
                "message": (f"Please try again in {retry_after} seconds" if retry_after else "Too many requests"),
            }, HTTPStatus.TOO_MANY_REQUESTS

        return (
            render_template(
                "errors/429.html",
                error={
                    "message": "Too many requests. Please try again later.",
                    "retry_after": retry_after,
                },
            ),
            429,
        )

    @app.errorhandler(403)
    def forbidden_error(error):
        return (
            render_template(
                "errors/403.html",
                error={"message": getattr(error, "description", None)},
            ),
            403,
        )

    # Add context processor for CSP nonce
    @app.context_processor
    def utility_processor():
        def csp_nonce():
            return getattr(request, "csp_nonce", "")

        return {"csp_nonce": csp_nonce}

    # Main routes
    @app.route("/")
    @login_required
    def index():
        if session.get("is_admin"):
            return redirect(url_for("users.dashboard"))
        return redirect(url_for("connections.view_connections"))

    @app.route("/test-api-connection")
    def test_api_connection():
        try:
            logger.info(f"Testing connection to API at {app.config['API_URL']}")
            response = requests.get(f"{app.config['API_URL']}/api/health", timeout=10)
            logger.info(f"API Response: Status={response.status_code}, Content={response.text}")
            return jsonify(
                {
                    "api_url": app.config["API_URL"],
                    "status_code": response.status_code,
                    "response": response.text,
                }
            )
        except Exception as e:
            logger.error(f"Error connecting to API: {str(e)}")
            return jsonify({"error": str(e), "api_url": app.config["API_URL"]}), 500

    # Health check endpoint
    @app.route("/health")
    def health_check():
        return {"status": "healthy"}, 200

    # Register custom template filters
    @app.template_filter("datetime")
    def format_datetime(value, date_format="%Y-%m-%d %H:%M:%S"):
        """Format a datetime object or ISO string to a readable string format.

        Args:
            value: The datetime object or ISO format string
            date_format: The output format string

        Returns:
            str: Formatted datetime string
        """
        if value is None:
            return ""

        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                return value

        if isinstance(value, datetime):
            return value.strftime(date_format)

        return value

    logger.info("=== Starting Frontend Application ===")
    return app
