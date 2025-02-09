import os
import logging

class Config:
    """Application configuration class"""
    
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your_secret_key')
    
    # API endpoints
    API_URL = os.environ.get('API_URL', 'http://desktop-api:5000')
    GUACAMOLE_URL = os.environ.get('GUACAMOLE_URL', 'http://guacamole:8080')
    EXTERNAL_GUACAMOLE_URL = os.environ.get('EXTERNAL_GUACAMOLE_URL', GUACAMOLE_URL+'/guacamole')
    
    # Logging configuration
    LOG_LEVEL = logging.INFO
    
    # Session configuration
    SESSION_TYPE = 'filesystem'
    PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes
    
    # Security configuration
    JWT_ALGORITHM = 'HS256'
    
    # CORS configuration
    CORS_ALLOWED_ORIGINS = [
        'http://localhost:5000',
        'http://localhost:5001',
        API_URL
    ]
    CORS_SUPPORTS_CREDENTIALS = True
    CORS_EXPOSE_HEADERS = [
        'Content-Range',
        'X-Total-Count'
    ]
    CORS_ALLOWED_HEADERS = [
        'Content-Type',
        'Authorization',
        'X-Requested-With',
        'Accept',
        'Origin'
    ]
    CORS_ALLOWED_METHODS = [
        'GET',
        'POST',
        'PUT',
        'DELETE',
        'OPTIONS'
    ]
    CORS_MAX_AGE = 3600  # 1 hour
    
    # Rate limiting configuration
    RATE_LIMIT_DEFAULT_SECOND = 10   # 10 requests per second
    RATE_LIMIT_DEFAULT_MINUTE = 30   # 30 requests per minute
    RATE_LIMIT_DEFAULT_HOUR = 1000   # 1000 requests per hour
    
    # Content Security Policy
    CSP_POLICY = {
        'default-src': ["'self'"],
        'script-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", 'data:'],
        'font-src': ["'self'"],
        'connect-src': ["'self'", API_URL]
    }
