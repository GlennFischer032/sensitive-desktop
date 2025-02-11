from flask import Blueprint, request, jsonify
from typing import List, Dict, Any, Optional
from desktop_manager.core.auth import token_required, admin_required
from desktop_manager.api.models.base import get_db
from desktop_manager.api.models.connection import Connection
from desktop_manager.api.schemas.connection import (
    ConnectionCreate,
    ConnectionResponse,
    ConnectionList,
    ConnectionScaleUp,
    ConnectionScaleDown
)
from desktop_manager.utils.utils import sanitize_name, generate_unique_connection_name, generate_random_string
from desktop_manager.core.guacamole import (
    guacamole_login,
    ensure_admins_group,
    create_guacamole_connection,
    grant_user_permission_on_connection,
    grant_group_permission_on_connection,
    delete_guacamole_connection
)
from desktop_manager.core.rancher import RancherAPI, DesktopValues
from desktop_manager.config.settings import get_settings
import yaml
from sqlalchemy.exc import IntegrityError
import logging
from http import HTTPStatus

connections_bp = Blueprint('connections_bp', __name__)

@connections_bp.route('/scaleup', methods=['POST'])
@token_required
def scale_up() -> tuple[Dict[str, Any], int]:
    """
    Scale up a new desktop connection.
    
    This endpoint creates a new desktop connection by:
    1. Validating the input data
    2. Creating a Rancher deployment
    3. Setting up a Guacamole connection
    4. Storing the connection details in the database
    
    Returns:
        tuple: A tuple containing:
            - Dict with connection details or error message
            - HTTP status code
    """
    logging.info("=== Received request to /scaleup ===")
    logging.info(f"Request path: {request.path}")
    logging.info(f"Request method: {request.method}")
    logging.info(f"Request headers: {request.headers}")
    
    db_session = next(get_db())
    try:
        # Validate input data using Pydantic
        data = request.get_json()
        scale_up_data = ConnectionScaleUp(**data)
        
        # Sanitize and generate unique name
        base_name = sanitize_name(scale_up_data.name)
        logging.info(f"Sanitized base name: {base_name}")
        name = generate_unique_connection_name(base_name, db_session)
        logging.info(f"Generated unique name: {name}")

        # Create Rancher API client
        logging.info("Creating Rancher API client...")
        settings = get_settings()
        rancher_api = RancherAPI(
            settings.RANCHER_API_URL,
            settings.RANCHER_API_TOKEN,
            settings.RANCHER_CLUSTER_ID,
            settings.RANCHER_REPO_NAME,
            settings.NAMESPACE
        )

        # Generate connection details
        connection_id = generate_random_string()
        vnc_password = generate_random_string(32)
        logging.info(f"Generated connection ID: {connection_id}")

        # Install the Helm chart
        logging.info("Installing Helm chart...")
        try:
            values = DesktopValues(
                name=name,
                image=settings.DESKTOP_IMAGE,
                imagePullPolicy="Always",
                serviceType="NodePort",
                vncPassword=vnc_password
            )
            
            response = rancher_api.install_chart(name, settings.NAMESPACE, values)
            logging.info(f"Install chart response: {response.text}")
            if response.status_code >= HTTPStatus.BAD_REQUEST:
                raise Exception(f"Failed to install chart: {response.text}")
            
            operation_data = response.json()
            logging.info(f"Operation data: {operation_data}")
            
            ip_address = f"{settings.NAMESPACE}-{name}.dyn.cloud.e-infra.cz"
            logging.info(f"Using VNC URL: {ip_address}")
        except Exception as e:
            logging.error(f"Failed to install Helm chart: {str(e)}")
            raise

        # Create Guacamole connection
        logging.info("Logging into Guacamole...")
        guacamole_token = guacamole_login()
        logging.info("Ensuring admins group...")
        ensure_admins_group(guacamole_token)
        logging.info("Creating Guacamole connection...")
        try:
            guacamole_connection_id = create_guacamole_connection(
                guacamole_token,
                name,
                ip_address,
                vnc_password
            )
            logging.info(f"Created Guacamole connection with ID: {guacamole_connection_id}")
        except Exception as e:
            logging.error(f"Failed to create Guacamole connection: {str(e)}")
            try:
                rancher_api.uninstall_chart(name, settings.NAMESPACE)
                logging.info("Cleaned up Rancher resources after Guacamole connection failure")
            except Exception as cleanup_error:
                logging.error(f"Failed to clean up Rancher resources: {cleanup_error}")
            raise

        # Grant permissions
        logging.info("Granting permissions...")
        try:
            grant_group_permission_on_connection(
                guacamole_token,
                'admins',
                guacamole_connection_id
            )
            logging.info("Granted admin group permissions")
            grant_user_permission_on_connection(
                guacamole_token,
                request.current_user.username,
                guacamole_connection_id
            )
            logging.info(f"Granted user permissions to {request.current_user.username}")
        except Exception as e:
            logging.error(f"Failed to grant permissions: {str(e)}")
            try:
                rancher_api.uninstall_chart(name, settings.NAMESPACE)
                delete_guacamole_connection(guacamole_token, guacamole_connection_id)
                logging.info("Cleaned up resources after permission failure")
            except Exception as cleanup_error:
                logging.error(f"Failed to clean up resources: {cleanup_error}")
            raise

        # Create connection in database
        logging.info("Creating connection in database...")
        try:
            new_connection = Connection(
                name=name,
                created_by=request.current_user.username,
                guacamole_connection_id=str(guacamole_connection_id)
            )
            db_session.add(new_connection)
            db_session.commit()
            logging.info("Connection created in database successfully")
            
            # Create response using Pydantic model
            response_data = ConnectionResponse(
                id=new_connection.id,
                name=new_connection.name,
                created_by=new_connection.created_by,
                created_at=new_connection.created_at,
                guacamole_connection_id=new_connection.guacamole_connection_id
            )
            
            return jsonify({
                'message': 'Connection scaled up successfully',
                'connection': response_data.model_dump()
            }), HTTPStatus.OK

        except Exception as e:
            logging.error(f"Failed to create database entry: {str(e)}")
            try:
                rancher_api.uninstall_chart(name, settings.NAMESPACE)
                delete_guacamole_connection(guacamole_token, guacamole_connection_id)
                logging.info("Cleaned up resources after database failure")
            except Exception as cleanup_error:
                logging.error(f"Failed to clean up resources: {cleanup_error}")
            db_session.rollback()
            raise

    except Exception as e:
        logging.error(f"Error in scale_up: {str(e)}")
        db_session.rollback()
        return jsonify({'error': str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR
    finally:
        db_session.close()

@connections_bp.route('/scaledown', methods=['POST'])
@token_required
def scale_down():
    """
    Scale down a connection
    ---
    tags:
      - connections
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              name:
                type: string
            required:
              - name
    responses:
      200:
        description: Connection scaled down successfully
        content:
          application/json:
            schema:
              type: object
              properties:
                message:
                  type: string
      400:
        description: Bad request
      500:
        description: Internal server error
    """
    logging.info(f"=== Received request to /scaledown ===")
    logging.info(f"Request path: {request.path}")
    logging.info(f"Request method: {request.method}")
    logging.info(f"Request headers: {request.headers}")
    db_session = next(get_db())
    try:
        data = request.get_json()
        name = data.get('name')
        if not name:
            return jsonify({'error': 'Name is required'}), 400

        # Get connection from database
        connection = db_session.query(Connection).filter_by(name=name).first()
        if not connection:
            return jsonify({'error': 'Connection not found'}), 404

        # Create Rancher API client
        settings = get_settings()
        rancher_api = RancherAPI(
            settings.RANCHER_API_URL,
            settings.RANCHER_API_TOKEN,
            settings.RANCHER_CLUSTER_ID,
            settings.RANCHER_REPO_NAME,
            settings.NAMESPACE
        )

        # Uninstall Helm chart
        rancher_api.uninstall_chart(name, settings.NAMESPACE)

        # Delete Guacamole connection
        guacamole_token = guacamole_login()
        delete_guacamole_connection(guacamole_token, connection.guacamole_connection_id)

        # Delete connection from database
        db_session.delete(connection)
        db_session.commit()

        return jsonify({'message': 'Connection scaled down successfully'}), 200

    except Exception as e:
        db_session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db_session.close()

@connections_bp.route('/list', methods=['GET'])
@token_required
def list_connections() -> tuple[Dict[str, Any], int]:
    """
    List all connections.
    
    Returns a list of all connections in the system, including their details
    such as name, creation time, creator, and Guacamole connection ID.
    
    Returns:
        tuple: A tuple containing:
            - Dict with list of connections or error message
            - HTTP status code
    """
    logging.info("=== Received request to /list ===")
    logging.info(f"Request path: {request.path}")
    logging.info(f"Request method: {request.method}")
    logging.info(f"Request headers: {request.headers}")
    
    db_session = next(get_db())
    try:
        connections = db_session.query(Connection).all()
        
        # Create response using Pydantic model
        response_data = ConnectionList(
            connections=[
                ConnectionResponse(
                    id=c.id,
                    name=c.name,
                    created_at=c.created_at,
                    created_by=c.created_by,
                    guacamole_connection_id=c.guacamole_connection_id
                ) for c in connections
            ]
        )
        
        logging.info(f"Found {len(connections)} connections")
        return jsonify(response_data.model_dump()), HTTPStatus.OK
    except Exception as e:
        logging.error(f"Error listing connections: {str(e)}")
        return jsonify({'error': str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR
    finally:
        db_session.close()

@connections_bp.route('/<connection_name>', methods=['GET'])
@token_required
def get_connection(connection_name):
    """
    Get a connection
    ---
    tags:
      - connections
    responses:
      200:
        description: Connection information
        content:
          application/json:
            schema:
              type: object
              properties:
                connection:
                  type: object
                  properties:
                    name:
                      type: string
                    created_at:
                      type: string
                    created_by:
                      type: string
      404:
        description: Connection not found
      500:
        description: Internal server error
    """
    logging.info(f"=== Received request to /{connection_name} ===")
    logging.info(f"Request path: {request.path}")
    logging.info(f"Request method: {request.method}")
    logging.info(f"Request headers: {request.headers}")
    db_session = next(get_db())
    try:
        connection = db_session.query(Connection).filter_by(name=connection_name).first()
        if not connection:
            return jsonify({'error': 'Connection not found'}), 404

        return jsonify({
            'connection': {
                'name': connection.name,
                'created_at': connection.created_at.isoformat(),
                'created_by': connection.created_by
            }
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db_session.close()
