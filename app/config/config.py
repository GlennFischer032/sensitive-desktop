import os
import logging

class Config:
    """Application configuration class"""
    
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your_secret_key')
    
    # API endpoints
    API_URL = os.environ.get('API_URL', 'http://desktop-api:5000')
    GUACAMOLE_URL = os.environ.get('GUACAMOLE_URL', 'http://guacamole:8080')
    
    # Logging configuration
    LOG_LEVEL = logging.INFO
    
    # Session configuration
    SESSION_TYPE = 'filesystem'
    PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes
    
    # Security configuration
    JWT_ALGORITHM = 'HS256'
