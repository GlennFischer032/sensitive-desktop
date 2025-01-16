# routes/users_routes.py

from flask import Blueprint, request, jsonify
from auth import token_required, admin_required
from guacamole import (
    guacamole_login,
    remove_user_from_group,
    delete_guacamole_user
)
from config import Config
import requests
from datetime import datetime
from database import get_db
from models import User

users_bp = Blueprint('users_bp', __name__)

@users_bp.route('/removeuser', methods=['POST'])
@token_required
@admin_required
def remove_user():
    """Remove a user
    ---
    tags:
      - users
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              username:
                type: string
            required:
              - username
    responses:
      200:
        description: User removed successfully
        content:
          application/json:
            schema:
              type: object
              properties:
                message:
                  type: string
      400:
        description: Bad request
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
      403:
        description: Forbidden
        content:
          application/json:
            schema:
              type: object              
              properties:
                error:
                  type: string
      500:
        description: Internal server error
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
                details:
                  type: string
    """
    data = request.get_json()
    username = data.get('username')

    if not username:
        return jsonify({'error': "Missing 'username' parameter"}), 400

    # Only prevent deletion of the Guacamole service user
    if username == Config.GUACAMOLE_USERNAME:
        return jsonify({'error': "Cannot remove service user"}), 403

    try:
        token = guacamole_login()
        # Remove user from 'all_users' group
        try:
            remove_user_from_group(token, username, 'all_users')
        except Exception as e:
            print(f"Failed to remove user '{username}' from 'all_users' group: {str(e)}")
            # Proceed even if removing from group fails

        # Delete user from Guacamole
        delete_guacamole_user(token, username)

        # Remove user from application's database
        try:
            db_session = next(get_db())
            user = db_session.query(User).filter(User.username == username).first()
            if user:
                db_session.delete(user)
                db_session.commit()
        except Exception as e:
            db_session.rollback()
            return jsonify({'error': 'Failed to remove user from the database', 'details': str(e)}), 500

        return jsonify({'message': f"User '{username}' removed successfully."}), 200
    except Exception as e:
        return jsonify({'error': 'Failed to remove user', 'details': str(e)}), 500

@users_bp.route('/createuser', methods=['POST'])
@token_required
@admin_required
def create_user():
    """Create a new user
    ---
    tags:
      - users
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              username:
                type: string
              password:
                type: string
              is_admin:
                type: boolean
            required:
              - username
              - password
    responses:
      201:
        description: User created successfully
        content:
          application/json:
            schema:
              type: object
              properties:
                message:
                  type: string
      400:
        description: Bad request
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
      500:
        description: Internal server error
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
                details:
                  type: string
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
        
    username = data.get('username')
    password = data.get('password')
    is_admin = data.get('is_admin', False)

    if not username or not password:
        return jsonify({'error': "Missing 'username' or 'password' parameter"}), 400

    try:
        # Create user in Guacamole
        token = guacamole_login()
        user_url = f'{Config.GUACAMOLE_API_URL}/session/data/mysql/users?token={token}'
        user_data = {
            'username': username,
            'password': password,
            'attributes': {
                'guac-full-name': username,
                'guac-organization': 'Desktop Manager',
                'expired': '',
                'disabled': '',
                'access-window-start': '',
                'access-window-end': '',
                'valid-from': '',
                'valid-until': '',
                'timezone': None
            }
        }

        response = requests.post(user_url, json=user_data)
        if response.status_code != 200:
            return jsonify({'error': f'Failed to create user in Guacamole: {response.text}'}), 500

        # Add user to database
        try:
            from werkzeug.security import generate_password_hash
            db_session = next(get_db())
            user = User(
                username=username, 
                password_hash=generate_password_hash(password),
                is_admin=is_admin
            )
            db_session.add(user)
            db_session.commit()
        except Exception as e:
            db_session.rollback()
            # Delete user from Guacamole if database fails
            delete_url = f'{Config.GUACAMOLE_API_URL}/session/data/mysql/users/{username}?token={token}'
            requests.delete(delete_url)
            return jsonify({'error': 'Failed to add user to database', 'details': str(e)}), 500

        return jsonify({'message': f"User '{username}' created successfully"}), 201
    except requests.exceptions.RequestException as e:
        return jsonify({'error': 'Failed to create user in Guacamole', 'details': str(e)}), 500
    except Exception as e:
        return jsonify({'error': 'Failed to create user', 'details': str(e)}), 500

@users_bp.route('/list', methods=['GET'])
@token_required
@admin_required
def list_users():
    """List all users
    ---
    tags:
      - users
    responses:
      200:
        description: List of users
        content:
          application/json:
            schema:
              type: object
              properties:
                users:
                  type: array
                  items:
                    type: object
                    properties:
                      username:
                        type: string
                      attributes:
                        type: object
                      lastActive:
                        type: string
                      is_admin:
                        type: boolean
      500:
        description: Internal server error
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
                details:
                  type: string
    """
    try:
        # Get users from Guacamole
        token = guacamole_login()
        users_url = f'{Config.GUACAMOLE_API_URL}/session/data/mysql/users?token={token}'
        headers = {
            'Content-Type': 'application/json'
        }
        response = requests.get(users_url, headers=headers)
        response.raise_for_status()
        guacamole_users = response.json()

        # Get users from database
        db_session = next(get_db())
        db_users = {user.username: user for user in db_session.query(User).all()}

        # Combine the data
        users_list = []
        for username, user_info in guacamole_users.items():
            # Exclude guacamole service user
            if username == Config.GUACAMOLE_USERNAME:
                continue

            # Convert lastActive timestamp to ISO format
            last_active_timestamp = user_info.get('lastActive')
            if last_active_timestamp:
                # Convert milliseconds to seconds and then to datetime
                last_active_datetime = datetime.utcfromtimestamp(last_active_timestamp / 1000).isoformat() + 'Z'
            else:
                last_active_datetime = None

            # Get additional info from database
            db_user = db_users.get(username)
            is_admin = db_user.is_admin if db_user else False

            user_details = {
                'username': username,
                'attributes': user_info.get('attributes', {}),
                'lastActive': last_active_datetime,
                'is_admin': is_admin
            }
            users_list.append(user_details)

        return jsonify({'users': users_list}), 200
    except Exception as e:
        return jsonify({'error': 'Failed to retrieve users', 'details': str(e)}), 500
