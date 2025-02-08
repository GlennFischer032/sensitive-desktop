from functools import wraps
from flask import session, redirect, url_for, flash, current_app
import jwt

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get('token')
        if not token:
            current_app.logger.info("No token found in session, redirecting to login")
            return redirect(url_for('login'))
        try:
            current_app.logger.info(f"Attempting to decode token with secret key: {current_app.config['SECRET_KEY'][:5]}...")
            decoded = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            current_app.logger.info(f"Successfully decoded token: {decoded}")
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            current_app.logger.info("Token expired, redirecting to login")
            session.clear()
            flash('Session expired. Please log in again.')
            return redirect(url_for('login'))
        except jwt.InvalidTokenError:
            current_app.logger.info("Invalid token, redirecting to login")
            session.clear()
            flash('Invalid token. Please log in again.')
            return redirect(url_for('login'))
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Admin access required.')
            return redirect(url_for('view_connections'))
        return f(*args, **kwargs)
    return decorated_function
