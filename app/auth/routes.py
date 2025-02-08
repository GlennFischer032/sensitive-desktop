from flask import render_template, request, redirect, url_for, session, flash, current_app
import requests
from . import auth_bp
from utils.decorators import login_required, admin_required

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please provide both username and password')
            return render_template('login.html')
        
        try:
            current_app.logger.info(f"Attempting login for user: {username}")
            response = requests.post(
                f'{current_app.config["API_URL"]}/api/auth/login',
                json={'username': username, 'password': password},
                timeout=5
            )
            current_app.logger.info(f"Login response status: {response.status_code}")
            
            if response.status_code != 200:
                error_message = response.json().get('error', 'Unknown error occurred')
                current_app.logger.error(f"Login failed: {error_message}")
                flash('Login failed. Please check your credentials.')
                return render_template('login.html')
            
            data = response.json()
            session['token'] = data['token']
            session['username'] = data['username']
            session['is_admin'] = data['is_admin']
            
            current_app.logger.info(f"Login successful for {username}, is_admin: {session['is_admin']}")
            
            if session['is_admin']:
                return redirect(url_for('users.dashboard'))
            return redirect(url_for('connections.view_connections'))
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"Login error: {str(e)}")
            current_app.logger.error(f"Full error details: {e.response.text if hasattr(e, 'response') else 'No response'}")
            flash('Login failed. Please check your credentials.')
            return render_template('login.html')
    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    current_app.logger.info("Logging out user")
    session.clear()
    return redirect(url_for('auth.login'))
