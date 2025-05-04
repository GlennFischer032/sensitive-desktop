"""Request logging middleware for the application."""
import logging
import os
from datetime import datetime

from flask import g, request, session

# Configure logger
logger = logging.getLogger("request_logger")
# Prevent propagation to parent loggers to avoid duplicate logs
logger.propagate = False

# Create handlers if not already created
if not logger.handlers:
    # Console handler
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # File handler
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
    os.makedirs(log_dir, exist_ok=True)

    file_handler = logging.FileHandler(os.path.join(log_dir, "requests.log"))
    file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)


def init_request_logging(app):
    """Initialize request logging for the application.

    Args:
        app: The Flask application
    """
    # Configure Werkzeug logger - set level to WARNING to suppress access logs
    werkzeug_logger = logging.getLogger("werkzeug")
    if app.config.get("WERKZEUG_LOG_LEVEL", "WARNING") == "WARNING":
        werkzeug_logger.setLevel(logging.WARNING)
    else:
        # Keep Werkzeug logs if explicitly configured to do so
        werkzeug_logger.setLevel(getattr(logging, app.config.get("WERKZEUG_LOG_LEVEL", "INFO")))

    @app.before_request
    def log_request():
        """Log details of every incoming request."""
        # Get current timestamp
        timestamp = datetime.now().isoformat()

        # Get request method and path
        method = request.method
        path = request.path

        # Get username if available in session
        username = session.get("username", "anonymous")

        # Get IP address
        ip_address = request.remote_addr

        # Create log message
        log_message = f"Request: {method} {path} - User: {username} - IP: {ip_address}"

        # Store request info in g for potential additional logging
        g.request_start_time = timestamp
        g.username = username

        # Log the request
        logger.info(log_message)

    @app.after_request
    def log_response(response):
        """Log response status code and processing time."""
        # Get request method and path
        method = request.method
        path = request.path

        # Get status code
        status_code = response.status_code

        # Get username if available
        username = getattr(g, "username", "anonymous")

        # Create log message
        log_message = f"Response: {method} {path} - Status: {status_code} - User: {username}"

        # Log the response
        logger.info(log_message)

        return response
