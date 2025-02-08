from flask import Blueprint

connections_bp = Blueprint('connections', __name__, url_prefix='/connections')

# Import routes to register them with the blueprint
from . import routes
