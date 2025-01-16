# app.py

import json
from flask import Flask, jsonify
from flask_cors import CORS
from routes.auth_routes import auth_bp
from routes.connection_routes import connections_bp
from routes.user_routes import users_bp
from database import init_db, get_db
from models import User
from guacamole import guacamole_login, create_guacamole_user_if_not_exists, ensure_admins_group, add_user_to_group
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import os

# Add logging configuration
logging.basicConfig(level=logging.INFO)

def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key')
    CORS(app)
    
    # Load environment variables into Flask config
    app.config['ADMIN_USERNAME'] = os.environ.get('ADMIN_USERNAME')
    app.config['ADMIN_PASSWORD'] = os.environ.get('ADMIN_PASSWORD')
    
    # Initialize database
    init_db()

    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(connections_bp, url_prefix='/api/connections')
    app.register_blueprint(users_bp, url_prefix='/api/users')

    # Enable CORS
    @app.after_request
    def after_request(response):
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
        return response

    # Initialize admin user
    with app.app_context():
        try:
            initialize_admin_user(app)
        except Exception as e:
            logging.error(f"Error during initialization: {str(e)}")

    @app.route('/api/health')
    def health_check():
        return jsonify({"status": "healthy"}), 200

    app.logger.setLevel(logging.INFO)
    app.logger.info("=== Starting API Application ===")

    return app

def initialize_admin_user(app):
    db_session = next(get_db())
    try:
        # Get admin credentials from config
        admin_username = app.config.get('ADMIN_USERNAME')
        admin_password = app.config.get('ADMIN_PASSWORD')

        if not admin_username or not admin_password:
            logging.error("ADMIN_USERNAME and ADMIN_PASSWORD must be set in environment variables.")
            return

        # Check if admin user already exists
        existing_admin = db_session.query(User).filter_by(username=admin_username).first()
        
        if existing_admin:
            logging.info(f"Admin user '{admin_username}' already exists")
            # Update password if it has changed
            if not check_password_hash(existing_admin.password_hash, admin_password):
                existing_admin.password_hash = generate_password_hash(admin_password)
                db_session.commit()
                logging.info(f"Updated password for admin user '{admin_username}'")
        else:
            # Create admin user
            admin_user = User(
                username=admin_username,
                password_hash=generate_password_hash(admin_password),
                is_admin=True
            )
            db_session.add(admin_user)
            try:
                db_session.commit()
                logging.info(f"Admin user '{admin_username}' created successfully")
            except Exception as e:
                logging.error(f"Failed to create admin user: {str(e)}")
                db_session.rollback()
                return

        # Try to set up Guacamole admin user and group
        try:
            # First login to Guacamole to get a token
            token = guacamole_login()
            
            # Then use the token for subsequent operations
            create_guacamole_user_if_not_exists(token, admin_username, admin_password)
            ensure_admins_group(token)
            add_user_to_group(token, admin_username, 'admins')
            logging.info(f"Successfully set up Guacamole user and group for '{admin_username}'")
        except Exception as e:
            logging.error(f"Failed to add admin user '{admin_username}' to 'admins' group in Guacamole: {str(e)}")
            logging.warning("This error is non-fatal, the application will continue to run")
    except Exception as e:
        logging.error(f"Error initializing admin user: {str(e)}")
        db_session.rollback()
    finally:
        db_session.close()

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0')
