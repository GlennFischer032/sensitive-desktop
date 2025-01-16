from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import requests
from functools import wraps
import jwt
import os
import logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key')

# Get API URL from environment variable with fallback
API_URL = os.environ.get('API_URL', 'http://desktop-api:5000')
GUACAMOLE_URL = os.environ.get('GUACAMOLE_URL', 'http://guacamole:8080')

app.logger.setLevel(logging.INFO)
app.logger.info("=== Starting Frontend Application ===")
app.logger.info(f"Using API_URL: {API_URL}")
app.logger.info(f"Using GUACAMOLE_URL: {GUACAMOLE_URL}")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get('token')
        if not token:
            app.logger.info("No token found in session, redirecting to login")
            return redirect(url_for('login'))
        try:
            jwt.decode(token, app.secret_key, algorithms=['HS256'])
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            app.logger.info("Token expired, redirecting to login")
            session.clear()
            flash('Session expired. Please log in again.')
            return redirect(url_for('login'))
        except jwt.InvalidTokenError:
            app.logger.info("Invalid token, redirecting to login")
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

@app.route('/')
@login_required
def index():
    if session.get('is_admin'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('view_connections'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect appropriately
    if 'token' in session:
        if session.get('is_admin'):
            return redirect(url_for('dashboard'))
        return redirect(url_for('view_connections'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            app.logger.info(f"Attempting login for user: {username}")
            login_url = f'{API_URL}/api/auth/login'
            app.logger.info(f"Login URL: {login_url}")
            
            # Authenticate user
            response = requests.post(login_url, json={
                'username': username,
                'password': password
            })
            app.logger.info(f"Login response status: {response.status_code}")
            app.logger.info(f"Login response content: {response.text}")
            
            response.raise_for_status()
            data = response.json()
            
            # Set session data from login response
            session['token'] = data['token']
            session['username'] = data['username']
            session['is_admin'] = data['is_admin']
            
            app.logger.info(f"Login successful for {username}, is_admin: {session['is_admin']}")
            
            if session['is_admin']:
                return redirect(url_for('dashboard'))
            return redirect(url_for('view_connections'))
        except requests.exceptions.RequestException as e:
            app.logger.error(f"Login error: {str(e)}")
            app.logger.error(f"Full error details: {e.response.text if hasattr(e, 'response') else 'No response'}")
            flash('Login failed. Please check your credentials.')
            return render_template('login.html')
    return render_template('login.html')

@app.route('/logout')
def logout():
    app.logger.info("Logging out user")
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
@admin_required
def dashboard():
    return render_template('dashboard.html')

# Users Management
@app.route('/users')
@login_required
@admin_required
def view_users():
    headers = {'Authorization': f'Bearer {session["token"]}'}
    try:
        app.logger.info("Fetching users from API...")
        response = requests.get(f'{API_URL}/api/users/list', headers=headers)
        app.logger.info(f"Response status code: {response.status_code}")
        app.logger.info(f"Response content: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            users = data.get('users', [])
            app.logger.info(f"Found {len(users)} users")
            return render_template('users.html', users=users)
        else:
            flash('Failed to fetch users')
            return render_template('users.html', users=[])
    except Exception as e:
        app.logger.error(f"Error fetching users: {str(e)}")
        flash(f'Error fetching users: {str(e)}')
        return render_template('users.html', users=[])

@app.route('/users/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    if request.method == 'POST':
        app.logger.info("=== add_user route accessed ===")
        app.logger.info(f"Request method: {request.method}")
        app.logger.info(f"Form data: {request.form}")
        app.logger.info(f"Token from session: {session.get('token')}")
        
        headers = {
            'Authorization': f'Bearer {session["token"]}',
            'Content-Type': 'application/json'
        }
        data = {
            'username': request.form['username'],
            'password': request.form['password'],
            'is_admin': 'is_admin' in request.form
        }
        try:
            app.logger.info("Making POST request to API...")
            app.logger.info(f"Request data: {data}")
            response = requests.post(f'{API_URL}/api/users/createuser', json=data, headers=headers, timeout=5)
            app.logger.info(f"Response status code: {response.status_code}")
            app.logger.info(f"Response content: {response.text}")
            
            if response.status_code == 201:
                flash('User added successfully')
                return redirect(url_for('view_users'))
            else:
                error_message = response.json().get('error', 'Unknown error occurred') if response.text else 'Empty response from server'
                flash(f'Failed to add user: {error_message}')
                app.logger.error(f"API returned error status {response.status_code}")
                app.logger.error(f"Error response: {response.text}")
        except requests.exceptions.Timeout:
            app.logger.error("Request to API timed out after 5 seconds")
            flash('Request to API timed out')
        except requests.exceptions.ConnectionError as e:
            app.logger.error(f"Connection error to API: {str(e)}")
            flash(f'Connection error: {str(e)}')
        except Exception as e:
            app.logger.error(f"Unexpected error: {str(e)}")
            flash(f'Error: {str(e)}')
        return render_template('add_user.html')
    return render_template('add_user.html')

@app.route('/users/delete/<username>', methods=['POST'])
@login_required
@admin_required
def delete_user(username):
    app.logger.info(f"=== delete_user route accessed for username: {username} ===")
    headers = {
        'Authorization': f'Bearer {session["token"]}',
        'Content-Type': 'application/json'
    }
    
    try:
        app.logger.info("Making DELETE request to API...")
        response = requests.post(
            f'{API_URL}/api/users/removeuser',
            headers=headers,
            json={'username': username},
            timeout=5
        )
        app.logger.info(f"Response status code: {response.status_code}")
        app.logger.info(f"Response content: {response.text}")
        
        if response.status_code == 200:
            flash('User deleted successfully')
        else:
            error_message = response.json().get('error', 'Unknown error occurred')
            flash(f'Failed to delete user: {error_message}')
            app.logger.error(f"API returned error status {response.status_code}")
            app.logger.error(f"Error response: {response.text}")
    except requests.exceptions.Timeout:
        app.logger.error("Request to API timed out after 5 seconds")
        flash('Request to API timed out')
    except requests.exceptions.ConnectionError as e:
        app.logger.error(f"Connection error to API: {str(e)}")
        flash(f'Connection error: {str(e)}')
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        flash(f'Error: {str(e)}')
    
    return redirect(url_for('view_users'))

# Connections Management
@app.route('/connections')
@login_required
def view_connections():
    try:
        headers = {'Authorization': f'Bearer {session["token"]}'}
        app.logger.info("Fetching connections from API...")
        response = requests.get(f'{API_URL}/api/connections/list', headers=headers, timeout=5)
        app.logger.info(f"Response status code: {response.status_code}")
        app.logger.info(f"Response content: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            connections = data.get('connections', [])
            # Filter connections for non-admin users
            if not session.get('is_admin'):
                connections = [conn for conn in connections if conn.get('created_by') == session.get('username')]
            app.logger.info(f"Found {len(connections)} connections")
            return render_template('connections.html', connections=connections)
        else:
            flash('Failed to fetch connections')
            return render_template('connections.html', connections=[])
    except Exception as e:
        app.logger.error(f"Error fetching connections: {str(e)}")
        flash(f'Error fetching connections: {str(e)}')
        return render_template('connections.html', connections=[])

@app.route('/connections/add', methods=['GET', 'POST'])
@login_required
def add_connection():
    app.logger.info("=== add_connection route accessed ===")
    app.logger.info(f"Request method: {request.method}")
    if request.method == 'POST':
        app.logger.info("=== Starting connection creation ===")
        app.logger.info(f"Form data: {request.form}")
        app.logger.info(f"Token from session: {session.get('token')}")
        
        headers = {'Authorization': f'Bearer {session["token"]}'}
        data = {
            'name': request.form['name']
        }
        url = f'{API_URL}/api/connections/scaleup'
        app.logger.info(f"Making request to: {url}")
        app.logger.info(f"Request data: {data}")
        app.logger.info(f"Request headers: {headers}")
        try:
            app.logger.info("Making POST request to API...")
            response = requests.post(url, json=data, headers=headers, timeout=5)
            app.logger.info(f"Response status code: {response.status_code}")
            app.logger.info(f"Response content: {response.text}")
            if response.status_code == 200:
                app.logger.info("Request successful, redirecting to view_connections")
                flash('Connection added successfully')
                return redirect(url_for('view_connections'))
            app.logger.error(f"API returned error status {response.status_code}")
            app.logger.error(f"Error response: {response.text}")
            flash(f'Failed to add connection: {response.text}')
        except requests.exceptions.Timeout:
            app.logger.error("Request to API timed out after 5 seconds")
            flash('Request to API timed out')
        except requests.exceptions.ConnectionError as e:
            app.logger.error(f"Connection error to API: {str(e)}")
            flash(f'Connection error: {str(e)}')
        except Exception as e:
            app.logger.error(f"Unexpected error: {str(e)}")
            flash(f'Error: {str(e)}')
    else:
        app.logger.info("Rendering add_connection.html template")
    return render_template('add_connection.html')

@app.route('/connections/delete/<connection_name>', methods=['POST'])
@login_required
def delete_connection(connection_name):
    headers = {'Authorization': f'Bearer {session["token"]}'}
    try:
        response = requests.post(f'{API_URL}/api/connections/scaledown', json={'name': connection_name}, headers=headers)
        app.logger.info(f"Delete connection response: {response.status_code} - {response.text}")
        
        if response.status_code == 200:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return '', 200
            flash('Connection deleted successfully')
        else:
            error_message = f'Failed to delete connection: {response.text}'
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return error_message, 400
            flash(error_message)
    except Exception as e:
        error_message = f'Error deleting connection: {str(e)}'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return error_message, 500
        flash(error_message)
    
    return redirect(url_for('view_connections'))

# Test endpoint for API connectivity
@app.route('/test-api-connection')
def test_api_connection():
    try:
        app.logger.info(f"Testing connection to API at {API_URL}")
        response = requests.get(f'{API_URL}/api/health')
        app.logger.info(f"API Response: Status={response.status_code}, Content={response.text}")
        return jsonify({
            'api_url': API_URL,
            'status_code': response.status_code,
            'response': response.text
        })
    except Exception as e:
        app.logger.error(f"Error connecting to API: {str(e)}")
        return jsonify({
            'error': str(e),
            'api_url': API_URL
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
