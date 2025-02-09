from flask import request, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from desktop_manager.api.models.user import User
from desktop_manager.api.models.base import get_db
import jwt
from datetime import datetime, timedelta
from functools import wraps

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # JWT is passed in the request header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]  # Remove 'Bearer ' prefix
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            db_session = next(get_db())
            current_user = db_session.query(User).filter(User.id == data['user_id']).first()
            if not current_user:
                return jsonify({'message': 'User not found!'}), 401
            # Attach user to request context
            request.current_user = current_user
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({'message': 'Invalid token!', 'details': str(e)}), 401
        except Exception as e:
            return jsonify({'message': 'An error occurred!', 'details': str(e)}), 401
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        current_user = getattr(request, 'current_user', None)
        if not current_user or not current_user.is_admin:
            return jsonify({'message': 'Admin privilege required!'}), 403
        return f(*args, **kwargs)
    return decorated
