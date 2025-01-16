import os
from flask import Blueprint, request, jsonify
from auth import token_required, admin_required
from database import get_db
from models import Connection
from utils import sanitize_name, generate_unique_connection_name, generate_random_string
from guacamole import (
    guacamole_login,
    ensure_admins_group,
    create_guacamole_connection,
    grant_user_permission_on_connection,
    grant_group_permission_on_connection,
    delete_guacamole_connection
)
from rancher import RancherAPI, DesktopValues
from config import Config
import yaml
from sqlalchemy.exc import IntegrityError
import logging

connections_bp = Blueprint('connections_bp', __name__)

@connections_bp.route('/scaleup', methods=['POST'])
@token_required
def scale_up():
    logging.info(f"=== Received request to /scaleup ===")
    logging.info(f"Request path: {request.path}")
    logging.info(f"Request method: {request.method}")
    logging.info(f"Request headers: {request.headers}")
    db_session = next(get_db())
    try:
        data = request.get_json()
        logging.info(f"Received scale up request with data: {data}")
        base_name = data.get('name')
        if not base_name:
            return jsonify({'error': 'Name is required'}), 400

        # Sanitize and generate unique name
        base_name = sanitize_name(base_name)
        logging.info(f"Sanitized base name: {base_name}")
        name = generate_unique_connection_name(base_name, db_session)
        logging.info(f"Generated unique name: {name}")

        # Create Rancher API client
        logging.info("Creating Rancher API client...")
        rancher_api = RancherAPI(
            Config.RANCHER_API_URL,
            Config.RANCHER_API_TOKEN,
            Config.RANCHER_CLUSTER_ID,
            Config.RANCHER_REPO_NAME,
            Config.NAMESPACE
        )

        # Generate a unique connection ID and a strong VNC password
        connection_id = generate_random_string()
        vnc_password = generate_random_string(32)  # 32 characters for strong security
        logging.info(f"Generated connection ID: {connection_id}")

        # Install the Helm chart with the VNC password
        logging.info("Installing Helm chart...")
        try:
            # Update DesktopValues to include VNC password
            values = DesktopValues(
                name=name,
                image=Config.DESKTOP_IMAGE,
                imagePullPolicy="Always",
                serviceType="NodePort",
                vncPassword=vnc_password  # Pass the VNC password to the desktop
            )
            
            response = rancher_api.install_chart(name, Config.NAMESPACE, values)
            logging.info(f"Install chart response: {response.text}")
            if response.status_code >= 400:
                raise Exception(f"Failed to install chart: {response.text}")
            
            # Get operation details from response
            operation_data = response.json()
            logging.info(f"Operation data: {operation_data}")
            operation_name = operation_data.get('operationName')
            operation_namespace = operation_data.get('operationNamespace')
            logging.info(f"Operation name: {operation_name}, namespace: {operation_namespace}")
            
            # Generate VNC URL using the Rancher namespace and release name
            ip_address = f"{Config.NAMESPACE}-{name}.dyn.cloud.e-infra.cz:5900"
            logging.info(f"Using VNC URL: {ip_address}")
        except Exception as e:
            logging.error(f"Failed to install Helm chart: {str(e)}")
            raise

        # Create Guacamole connection with the same VNC password
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
                vnc_password  # Use the same VNC password for Guacamole
            )
            logging.info(f"Created Guacamole connection with ID: {guacamole_connection_id}")
        except Exception as e:
            logging.error(f"Failed to create Guacamole connection: {str(e)}")
            # Clean up Rancher resources on failure
            try:
                rancher_api.uninstall_chart(name, Config.NAMESPACE)
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
            # Clean up Rancher and Guacamole resources on failure
            try:
                rancher_api.uninstall_chart(name, Config.NAMESPACE)
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
                guacamole_connection_id=str(guacamole_connection_id)  # Convert to string
            )
            db_session.add(new_connection)
            db_session.commit()
            logging.info("Connection created in database successfully")
        except Exception as e:
            logging.error(f"Failed to create database entry: {str(e)}")
            # Clean up all resources on database failure
            try:
                rancher_api.uninstall_chart(name, Config.NAMESPACE)
                delete_guacamole_connection(guacamole_token, guacamole_connection_id)
                logging.info("Cleaned up resources after database failure")
            except Exception as cleanup_error:
                logging.error(f"Failed to clean up resources: {cleanup_error}")
            db_session.rollback()
            raise

        return jsonify({
            'message': 'Connection scaled up successfully',
            'connection': {
                'name': name,
                'created_by': request.current_user.username,
                'created_at': new_connection.created_at.isoformat(),
                'guacamole_connection_id': str(guacamole_connection_id)  # Convert to string
            }
        }), 200

    except Exception as e:
        logging.error(f"Error in scale_up: {str(e)}")
        db_session.rollback()
        return jsonify({'error': str(e)}), 500
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
        rancher_api = RancherAPI(
            Config.RANCHER_API_URL,
            Config.RANCHER_API_TOKEN,
            Config.RANCHER_CLUSTER_ID,
            Config.RANCHER_REPO_NAME,
            Config.NAMESPACE
        )

        # Uninstall Helm chart
        rancher_api.uninstall_chart(name, Config.NAMESPACE)

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
def list_connections():
    """
    List all connections
    ---
    tags:
      - connections
    responses:
      200:
        description: List of connections
        content:
          application/json:
            schema:
              type: object
              properties:
                connections:
                  type: array
                  items:
                    type: object
                    properties:
                      name:
                        type: string
                      created_at:
                        type: string
                      created_by:
                        type: string
                      guacamole_connection_id:
                        type: string
      500:
        description: Internal server error
    """
    logging.info(f"=== Received request to /list ===")
    logging.info(f"Request path: {request.path}")
    logging.info(f"Request method: {request.method}")
    logging.info(f"Request headers: {request.headers}")
    
    db_session = next(get_db())
    try:
        connections = db_session.query(Connection).all()
        result = {
            'connections': [{
                'name': c.name,
                'created_at': c.created_at.isoformat(),
                'created_by': c.created_by,
                'guacamole_connection_id': c.guacamole_connection_id
            } for c in connections]
        }
        logging.info(f"Found {len(connections)} connections")
        return jsonify(result), 200
    except Exception as e:
        logging.error(f"Error listing connections: {str(e)}")
        return jsonify({'error': str(e)}), 500
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
