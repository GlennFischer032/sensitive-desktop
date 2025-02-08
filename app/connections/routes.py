from flask import render_template, request, redirect, url_for, session, flash, current_app, jsonify
import requests
from . import connections_bp
from utils.decorators import login_required, admin_required

@connections_bp.route('/')
@login_required
def view_connections():
    headers = {'Authorization': f'Bearer {session["token"]}'}
    try:
        current_app.logger.info("Fetching connections from API...")
        response = requests.get(f'{current_app.config["API_URL"]}/api/connections/list', headers=headers)
        current_app.logger.info(f"Response status code: {response.status_code}")
        current_app.logger.info(f"Response content: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            connections = data.get('connections', [])
            current_app.logger.info(f"Found {len(connections)} connections")
            return render_template('connections.html', connections=connections, guacamole_url=current_app.config['GUACAMOLE_URL'])
        else:
            flash('Failed to fetch connections')
            return render_template('connections.html', connections=[], guacamole_url=current_app.config['GUACAMOLE_URL'])
    except Exception as e:
        current_app.logger.error(f"Error fetching connections: {str(e)}")
        flash(f'Error fetching connections: {str(e)}')
        return render_template('connections.html', connections=[], guacamole_url=current_app.config['GUACAMOLE_URL'])

@connections_bp.route('/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_connection():
    if request.method == 'POST':
        connection_name = request.form.get('connection_name')
        
        if not connection_name:
            flash('Please provide a connection name')
            return render_template('add_connection.html')
        
        try:
            current_app.logger.info(f"Adding new connection: {connection_name}")
            api_url = f'{current_app.config["API_URL"]}/api/connections/scaleup'
            headers = {'Authorization': f'Bearer {session["token"]}', 'Content-Type': 'application/json'}
            data = {'name': connection_name}
            
            current_app.logger.info(f"Making request to: {api_url}")
            current_app.logger.info(f"Headers: {headers}")
            current_app.logger.info(f"Data: {data}")
            
            response = requests.post(api_url, headers=headers, json=data)
            
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
def delete_connection(connection_name):
    try:
        current_app.logger.info(f"Deleting connection: {connection_name}")
        response = requests.post(
            f'{current_app.config["API_URL"]}/api/connections/scaledown',
            headers={'Authorization': f'Bearer {session["token"]}', 'Content-Type': 'application/json'},
            json={'name': connection_name}
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
    
    return redirect(url_for('connections.view_connections'))
