from flask import render_template, request, redirect, url_for, session, flash, current_app, jsonify
import requests
from . import connections_bp
from utils.decorators import login_required, admin_required
from middleware.security import rate_limit

@connections_bp.route('/')
@login_required
@rate_limit(requests_per_minute=30)  # Standard rate limit for viewing connections
def view_connections():
    headers = {'Authorization': f'Bearer {session["token"]}'}
    try:
        current_app.logger.info("Fetching connections from API...")
        response = requests.get(
            f'{current_app.config["API_URL"]}/api/connections/list',
            headers=headers,
            timeout=10
        )
        current_app.logger.info(f"Response status code: {response.status_code}")
        current_app.logger.info(f"Response content: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            connections = data.get('connections', [])
            current_app.logger.info(f"Found {len(connections)} connections")
            return render_template('connections.html', 
                                connections=connections, 
                                guacamole_url=current_app.config['GUACAMOLE_URL'],
                                external_guacamole_url=current_app.config['EXTERNAL_GUACAMOLE_URL'])
        else:
            flash('Failed to fetch connections')
            return render_template('connections.html', 
                                connections=[], 
                                guacamole_url=current_app.config['GUACAMOLE_URL'],
                                external_guacamole_url=current_app.config['EXTERNAL_GUACAMOLE_URL'])
    except Exception as e:
        current_app.logger.error(f"Error fetching connections: {str(e)}")
        flash(f'Error fetching connections: {str(e)}')
        return render_template('connections.html', 
                            connections=[], 
                            guacamole_url=current_app.config['GUACAMOLE_URL'],
                            external_guacamole_url=current_app.config['EXTERNAL_GUACAMOLE_URL'])

@connections_bp.route('/add', methods=['GET', 'POST'])
@login_required
@admin_required
@rate_limit(requests_per_minute=10)  # Stricter limit for adding connections
def add_connection():
    if request.method == 'POST':
        connection_name = request.form.get('connection_name')
        
        if not connection_name:
            flash('Please provide a connection name')
            return render_template('add_connection.html')
        
        try:
            current_app.logger.info(f"Adding new connection: {connection_name}")
            api_url = f'{current_app.config["API_URL"]}/api/connections/scaleup'
            headers = {
                'Authorization': f'Bearer {session["token"]}',
                'Content-Type': 'application/json'
            }
            data = {'name': connection_name}
            
            current_app.logger.info(f"Making request to: {api_url}")
            current_app.logger.info(f"Headers: {headers}")
            current_app.logger.info(f"Data: {data}")
            
            response = requests.post(
                api_url,
                headers=headers,
                json=data,
                timeout=30  # Longer timeout for scaling up
            )
            
            current_app.logger.info(f"Response status: {response.status_code}")
            current_app.logger.info(f"Response content: {response.text}")
            
            if response.status_code == 200:
                flash('Connection added successfully')
                return redirect(url_for('connections.view_connections'))
            else:
                error_message = response.json().get('error', 'Unknown error occurred')
                current_app.logger.error(f"Failed to add connection: {error_message}")
                flash(f'Failed to add connection: {error_message}')
        except Exception as e:
            current_app.logger.error(f"Error adding connection: {str(e)}")
            flash(f'Error adding connection: {str(e)}')
    
    return render_template('add_connection.html')

@connections_bp.route('/delete/<connection_name>', methods=['POST'])
@login_required
@admin_required
@rate_limit(requests_per_minute=10)  # Stricter limit for deleting connections
def delete_connection(connection_name):
    try:
        current_app.logger.info(f"Deleting connection: {connection_name}")
        response = requests.post(
            f'{current_app.config["API_URL"]}/api/connections/scaledown',
            headers={
                'Authorization': f'Bearer {session["token"]}',
                'Content-Type': 'application/json'
            },
            json={'name': connection_name},
            timeout=30  # Longer timeout for scaling down
        )
        
        if response.status_code == 200:
            flash('Connection deleted successfully')
        else:
            error_message = response.json().get('error', 'Unknown error occurred')
            current_app.logger.error(f"Failed to delete connection: {error_message}")
            flash(f'Failed to delete connection: {error_message}')
    except Exception as e:
        current_app.logger.error(f"Error deleting connection: {str(e)}")
        flash(f'Error deleting connection: {str(e)}')
    
    # If it's an AJAX request, return JSON response
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'status': 'success'}), 200
        
    return redirect(url_for('connections.view_connections'))
