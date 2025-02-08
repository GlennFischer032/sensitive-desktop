from flask import Flask, render_template
import logging
from config.config import Config
from auth import auth_bp
from connections import connections_bp
from users import users_bp

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Configure logging
    logging.basicConfig(level=config_class.LOG_LEVEL)
    app.logger.setLevel(config_class.LOG_LEVEL)
    app.logger.info("=== Starting Frontend Application ===")
    app.logger.info(f"Using API_URL: {app.config['API_URL']}")
    app.logger.info(f"Using GUACAMOLE_URL: {app.config['GUACAMOLE_URL']}")

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(connections_bp)
    app.register_blueprint(users_bp)

    # Register error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        app.logger.error(f"Page not found: {error}")
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Server error: {error}")
        return render_template('errors/500.html'), 500

    @app.errorhandler(403)
    def forbidden_error(error):
        app.logger.error(f"Forbidden access: {error}")
        return render_template('errors/403.html'), 403

    # Register main routes
    from .routes import register_routes
    register_routes(app)

    return app