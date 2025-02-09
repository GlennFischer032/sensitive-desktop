# routes/users_routes.py

from flask import Blueprint, request, jsonify, current_app
from typing import Dict, Any, Tuple
from http import HTTPStatus
import logging
from datetime import datetime, timedelta
import jwt
import requests
from pydantic import ValidationError

from desktop_manager.core.auth import token_required, admin_required
from desktop_manager.core.guacamole import (
    guacamole_login,
    remove_user_from_group,
    delete_guacamole_user,
    create_guacamole_user,
    ensure_all_users_group,
    add_user_to_group
)
from desktop_manager.config.settings import get_settings
from desktop_manager.api.models.base import get_db
from desktop_manager.api.models.user import User
from desktop_manager.api.schemas.user import (
    UserCreate,
    UserResponse,
    UserList,
    UserLogin,
    UserUpdate,
    TokenResponse
)
from desktop_manager.api.utils.error_handlers import handle_validation_error
from werkzeug.security import generate_password_hash, check_password_hash

users_bp = Blueprint('users_bp', __name__)

@users_bp.route('/removeuser', methods=['POST'])
@token_required
@admin_required
def remove_user() -> Tuple[Dict[str, Any], int]:
    """
    Remove a user from the system.
    
    This endpoint removes a user from both the application database and Guacamole.
    It ensures proper cleanup of user resources.
    
    Returns:
        tuple: A tuple containing:
            - Dict with success/error message
            - HTTP status code
    """
    try:
        data = request.get_json()
        username = data.get('username')

        if not username:
            return jsonify({'error': 'Validation Error', 'details': {'username': ['This field is required']}}), HTTPStatus.BAD_REQUEST

        settings = get_settings()
        if username == settings.GUACAMOLE_USERNAME:
            return jsonify({'error': "Cannot remove service user"}), HTTPStatus.FORBIDDEN

        # Get database session
        db_session = next(get_db())
        try:
            # Check if user exists in database
            user = db_session.query(User).filter(User.username == username).first()
            if not user:
                return jsonify({'error': 'Not Found', 'details': {'username': ['User not found']}}), HTTPStatus.NOT_FOUND

            # Delete from Guacamole first
            token = guacamole_login()
            try:
                delete_guacamole_user(token, username)
                logging.info(f"User '{username}' removed from Guacamole")
            except Exception as e:
                logging.error(f"Failed to remove user from Guacamole: {str(e)}")
                raise

            # Then delete from database
            db_session.delete(user)
            db_session.commit()
            logging.info(f"User '{username}' removed from database")
                
            return jsonify({'message': f"User '{username}' removed successfully"}), HTTPStatus.OK

        except Exception as e:
            db_session.rollback()
            logging.error(f"Database error while removing user: {str(e)}")
            raise
        finally:
            db_session.close()

    except Exception as e:
        logging.error(f"Error removing user: {str(e)}")
        return jsonify({'error': str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR

@users_bp.route('/createuser', methods=['POST'])
@token_required
@admin_required
def create_user() -> Tuple[Dict[str, Any], int]:
    """
    Create a new user in the system.
    
    This endpoint creates a new user in both the application database and Guacamole.
    It validates the input data and ensures proper setup of user permissions and groups.
    
    Returns:
        tuple: A tuple containing:
            - Dict with success/error message
            - HTTP status code
    """
    try:
        # Validate input using Pydantic
        try:
            user_data = UserCreate(**request.get_json())
        except ValidationError as e:
            return handle_validation_error(e)
        
        settings = get_settings()
        token = guacamole_login()
        
        # Check if user already exists
        db_session = next(get_db())
        try:
            existing_user = db_session.query(User).filter(User.username == user_data.username).first()
            if existing_user:
                return jsonify({
                    'error': 'Validation Error',
                    'details': {'username': ['Username already exists']}
                }), HTTPStatus.BAD_REQUEST
        finally:
            db_session.close()
        
        # Create user in Guacamole
        try:
            create_guacamole_user(token, user_data.username, user_data.password)
            ensure_all_users_group(token)
            add_user_to_group(token, user_data.username, 'all_users')
        except Exception as e:
            logging.error(f"Failed to create user in Guacamole: {str(e)}")
            raise

        # Create user in database
        db_session = next(get_db())
        try:
            user = User(
                username=user_data.username,
                password_hash=generate_password_hash(user_data.password),
                is_admin=user_data.is_admin
            )
            db_session.add(user)
            db_session.commit()
            
            # Create response using Pydantic model
            response_data = UserResponse(
                id=user.id,
                username=user.username,
                is_admin=user.is_admin,
                created_at=user.created_at
            )
            
            return jsonify({
                'message': f"User '{user_data.username}' created successfully",
                'user': response_data.model_dump()
            }), HTTPStatus.CREATED
            
        except Exception as e:
            db_session.rollback()
            # Cleanup Guacamole user if database fails
            try:
                delete_guacamole_user(token, user_data.username)
            except Exception as cleanup_error:
                logging.error(f"Failed to cleanup Guacamole user after database error: {cleanup_error}")
            raise
        finally:
            db_session.close()

    except Exception as e:
        logging.error(f"Error creating user: {str(e)}")
        if isinstance(e, ValidationError):
            return handle_validation_error(e)
        return jsonify({
            'error': 'Internal Server Error',
            'details': str(e)
        }), HTTPStatus.INTERNAL_SERVER_ERROR

@users_bp.route('/list', methods=['GET'])
@token_required
@admin_required
def list_users() -> Tuple[Dict[str, Any], int]:
    """
    List all users in the system.
    
    This endpoint retrieves all users from both the application database
    and Guacamole, combining the information into a comprehensive response.
    
    Returns:
        tuple: A tuple containing:
            - Dict with list of users
            - HTTP status code
    """
    try:
        settings = get_settings()
        token = guacamole_login()
        
        # Get users from Guacamole
        users_url = f'{settings.GUACAMOLE_API_URL}/session/data/mysql/users?token={token}'
        response = requests.get(users_url)
        response.raise_for_status()
        guacamole_users = response.json()

        # Get users from database
        db_session = next(get_db())
        try:
            db_users = {user.username: user for user in db_session.query(User).all()}
            
            # Combine the data
            users_list = []
            for username, user_info in guacamole_users.items():
                # Exclude guacamole service user
                if username == settings.GUACAMOLE_USERNAME:
                    continue

                # Get last active time
                last_active = user_info.get('lastActive')
                if last_active:
                    last_active = datetime.utcfromtimestamp(last_active / 1000)

                # Get database info
                db_user = db_users.get(username)
                if db_user:
                    user_response = UserResponse(
                        id=db_user.id,
                        username=db_user.username,
                        is_admin=db_user.is_admin,
                        created_at=db_user.created_at
                    )
                    users_list.append(user_response)

            response_data = UserList(users=users_list)
            return jsonify(response_data.model_dump()), HTTPStatus.OK
            
        finally:
            db_session.close()

    except Exception as e:
        logging.error(f"Error listing users: {str(e)}")
        return jsonify({'error': str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR
