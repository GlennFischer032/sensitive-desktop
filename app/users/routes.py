from flask import render_template, request, redirect, url_for, session, flash, current_app
import requests
from . import users_bp
from utils.decorators import login_required, admin_required

@users_bp.route('/')
@login_required
@admin_required
def view_users():
    headers = {'Authorization': f'Bearer {session["token"]}'}
    try:
        current_app.logger.info("Fetching users from API...")
        response = requests.get(f'{current_app.config["API_URL"]}/api/users/list', headers=headers)
        current_app.logger.info(f"Response status code: {response.status_code}")
        current_app.logger.info(f"Response content: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            users = data.get('users', [])
            current_app.logger.info(f"Found {len(users)} users")
            return render_template('users.html', users=users)
        else:
            flash('Failed to fetch users')
            return render_template('users.html', users=[])
    except Exception as e:
        current_app.logger.error(f"Error fetching users: {str(e)}")
        flash(f'Error fetching users: {str(e)}')
        return render_template('users.html', users=[])

@users_bp.route('/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    if request.method == 'POST':
        current_app.logger.info("=== add_user route accessed ===")
        current_app.logger.info(f"Request method: {request.method}")
        current_app.logger.info(f"Form data: {request.form}")
        current_app.logger.info(f"Token from session: {session.get('token')}")
        
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
            current_app.logger.info("Making POST request to API...")
            current_app.logger.info(f"Request data: {data}")
            response = requests.post(f'{current_app.config["API_URL"]}/api/users/createuser', json=data, headers=headers, timeout=5)
            current_app.logger.info(f"Response status code: {response.status_code}")
            current_app.logger.info(f"Response content: {response.text}")
            
            if response.status_code == 201:
                flash('User added successfully')
                return redirect(url_for('users.view_users'))
            else:
                error_message = response.json().get('error', 'Unknown error occurred') if response.text else 'Empty response from server'
                flash(f'Failed to add user: {error_message}')
                current_app.logger.error(f"API returned error status {response.status_code}")
                current_app.logger.error(f"Error response: {response.text}")
        except requests.exceptions.Timeout:
            current_app.logger.error("Request to API timed out after 5 seconds")
            flash('Request to API timed out')
        except requests.exceptions.ConnectionError as e:
            current_app.logger.error(f"Connection error to API: {str(e)}")
            flash(f'Connection error: {str(e)}')
        except Exception as e:
            current_app.logger.error(f"Unexpected error: {str(e)}")
            flash(f'Error: {str(e)}')
        return render_template('add_user.html')
    return render_template('add_user.html')

@users_bp.route('/delete/<username>', methods=['POST'])
@login_required
@admin_required
def delete_user(username):
    try:
        current_app.logger.info(f"Attempting to delete user: {username}")
        if username == session.get('username'):
            flash('Cannot delete your own account')
            return redirect(url_for('users.view_users'))

        response = requests.delete(
            f'{current_app.config["API_URL"]}/api/users/delete/{username}',
            headers={'Authorization': f'Bearer {session["token"]}'}
        )
        
        if response.status_code == 200:
            flash('User deleted successfully')
        else:
            error_message = response.json().get('error', 'Unknown error occurred')
            current_app.logger.error(f"Failed to delete user: {error_message}")
            flash(f'Failed to delete user: {error_message}')
    except Exception as e:
        current_app.logger.error(f"Error deleting user: {str(e)}")
        flash(f'Error: {str(e)}')
    
    return redirect(url_for('users.view_users'))

@users_bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
    return render_template('dashboard.html')
