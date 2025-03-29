from flask import Blueprint

configurations_bp = Blueprint("configurations", __name__, url_prefix="/configurations")

# Import routes to register them with the blueprint
from app.configurations import routes
