from http import HTTPStatus
import logging
import uuid

from clients.factory import client_factory
from clients.guacamole import GuacamoleConnectionParameters
from clients.rancher import DesktopValues
from config.settings import get_settings
from database.repositories.connection import ConnectionRepository
from database.repositories.desktop_configuration import DesktopConfigurationRepository
from database.repositories.storage_pvc import StoragePVCRepository
from utils.encryption import decrypt_password
from utils.guacamole_json_auth import GuacamoleJsonAuth
from utils.utils import (
    generate_random_string,
    generate_unique_connection_name,
)


class APIError(Exception):
    """Base exception for API errors."""

    def __init__(self, message, status_code=HTTPStatus.INTERNAL_SERVER_ERROR):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class BadRequestError(APIError):
    """Raised when client sends invalid or incomplete data."""

    def __init__(self, message):
        super().__init__(message, HTTPStatus.BAD_REQUEST)


class NotFoundError(APIError):
    """Raised when a requested resource is not found."""

    def __init__(self, message):
        super().__init__(message, HTTPStatus.NOT_FOUND)


class ForbiddenError(APIError):
    """Raised when user doesn't have permission to access a resource."""

    def __init__(self, message):
        super().__init__(message, HTTPStatus.FORBIDDEN)


class UnauthorizedError(APIError):
    """Raised when authentication is required but missing or invalid."""

    def __init__(self, message):
        super().__init__(message, HTTPStatus.UNAUTHORIZED)


class ConnectionsService:
    """Service for managing desktop connections."""

    def validate_scale_up_input(self, data: dict):
        """Validate the input data for the scale_up endpoint."""
        if not data or "name" not in data:
            raise BadRequestError("Missing required field: name")

        # Validate name against the required pattern
        import re

        name_pattern = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")
        if not name_pattern.match(data["name"]):
            raise BadRequestError(
                "Connection name must start and end with an alphanumeric character "
                "and contain only lowercase letters, numbers, and hyphens"
            )

        # Check if name is too long (max 12 characters)
        if len(data["name"]) > 12:
            raise BadRequestError("Connection name is too long. Maximum length is 12 characters.")

    def validate_external_pvc(self, external_pvc: str, current_user, session):
        """Validate that the external PVC exists and the user has access to it."""
        logging.debug("External PVC specified: %s", external_pvc)
        try:
            pvc_repo = StoragePVCRepository(session)
            pvc = pvc_repo.get_by_name(external_pvc)
            if not pvc:
                raise NotFoundError(f"PVC '{external_pvc}' not found")

            allowed_users = [access.username for access in pvc.users]

            if current_user.is_admin:
                logging.debug("Admin user - access granted to PVC")
            elif pvc.is_public:
                logging.debug("Public PVC - access granted to all users")
            elif current_user.username not in allowed_users:
                raise ForbiddenError("You do not have permission to use this PVC")

            return pvc.id

        except APIError:
            # Re-raise API errors
            raise
        except Exception as e:
            logging.error("Error verifying PVC: %s", str(e))
            raise APIError(f"Error verifying PVC: {e!s}") from e

    def get_desktop_configuration(self, desktop_configuration_id, current_user, session):
        """Get desktop configuration details."""
        if desktop_configuration_id:
            config_repo = DesktopConfigurationRepository(session)
            config = config_repo.get_by_id(desktop_configuration_id)

            if not config:
                raise NotFoundError("Desktop configuration not found")

            allowed_users = [access.username for access in config.users]

            if config.is_public or current_user.is_admin or current_user.username in allowed_users:
                pass
            else:
                raise ForbiddenError("You do not have permission to use this configuration")

            desktop_image = config.image
            min_cpu = config.min_cpu
            max_cpu = config.max_cpu
            min_ram = config.min_ram
            max_ram = config.max_ram
        else:
            settings = get_settings()
            desktop_image = settings.DESKTOP_IMAGE
            desktop_configuration_id = None
            min_cpu = 1
            max_cpu = 4
            min_ram = "4096Mi"
            max_ram = "16384Mi"

        return desktop_image, min_cpu, max_cpu, min_ram, max_ram, desktop_configuration_id

    def provision_desktop_resources(
        self, name, vnc_password, desktop_image, min_cpu, max_cpu, min_ram, max_ram, persistent_home, external_pvc
    ):
        """Provision desktop resources using Rancher."""
        settings = get_settings()
        # Create Rancher API client
        rancher_client = client_factory.get_rancher_client()

        # Create desktop values
        desktop_values = DesktopValues(
            desktop=desktop_image,
            name=name,
            vnc_password=vnc_password,
            mincpu=min_cpu,
            maxcpu=max_cpu,
            minram=min_ram,
            maxram=max_ram,
            external_pvc=external_pvc,
            guacamole={
                "namespace": settings.NAMESPACE,
                "releaseName": settings.GUACAMOLE_RELEASE_NAME,
            }
            if not settings.DEBUG
            else None,
        )

        # Configure storage with persistent_home setting
        desktop_values.storage.persistenthome = persistent_home

        # Enable storage if external PVC is provided
        if external_pvc:
            desktop_values.storage.enable = True

        try:
            # Install Helm chart
            logging.debug("Installing Helm chart for %s", name)
            rancher_client.install(name, desktop_values)
            logging.debug("Helm chart installation completed")

            # Check if VNC server is ready
            logging.debug("Checking if VNC server is ready for %s", name)
            vnc_ready = rancher_client.check_vnc_ready(name)
            status = "ready" if vnc_ready else "provisioning"
            logging.debug("VNC server ready status for %s: %s", name, status)

            return status, rancher_client
        except Exception as e:
            logging.error("Rancher provisioning failed: %s", str(e))
            raise APIError(f"Failed to provision desktop: {e!s}") from e

    def save_connection_to_database(
        self,
        name,
        username,
        vnc_password,
        hostname,
        port,
        persistent_home,
        desktop_configuration_id,
        external_pvc,
        session,
    ):
        """Save connection details to the database."""
        try:
            conn_repo = ConnectionRepository(session)
            connection = conn_repo.create_connection(
                {
                    "name": name,
                    "created_by": username,
                    "vnc_password": vnc_password,
                    "hostname": hostname,
                    "port": port,
                    "persistent_home": persistent_home,
                    "desktop_configuration_id": desktop_configuration_id,
                }
            )

            # If external PVC was used, map it to the connection
            if external_pvc:
                try:
                    pvc_repo = StoragePVCRepository(session)
                    pvc = pvc_repo.get_by_name(external_pvc)
                    if not pvc:
                        raise NotFoundError(f"PVC '{external_pvc}' not found")

                    conn_repo = ConnectionRepository(session)
                    conn_repo.map_connection_to_pvc(connection.id, pvc.id)

                except Exception as e:
                    logging.error("Error mapping connection to PVC: %s", str(e))
                # Continue even if mapping fails

            return connection
        except Exception as e:
            logging.error("Database error: %s", str(e))
            raise APIError(f"Failed to save connection: {e!s}") from e

    def scale_up(self, data, current_user, session):
        """Scale up a new desktop connection."""
        logging.debug("=== Processing scale up request ===")
        settings = get_settings()
        # Validate input data
        self.validate_scale_up_input(data)

        # Extract and validate parameters
        persistent_home = data.get("persistent_home", True)
        external_pvc = data.get("external_pvc")

        # Validate external PVC if provided
        if external_pvc:
            self.validate_external_pvc(external_pvc, current_user, session)

        # Get desktop configuration
        desktop_image, min_cpu, max_cpu, min_ram, max_ram, desktop_configuration_id = self.get_desktop_configuration(
            data.get("desktop_configuration_id"), current_user, session
        )

        # Generate unique connection name and credentials
        name = generate_unique_connection_name(data["name"])
        logging.debug("Generated unique name: %s", name)
        vnc_password = generate_random_string(32)
        logging.debug("Generated VNC password")

        # Provision resources
        status, rancher_client = self.provision_desktop_resources(
            name, vnc_password, desktop_image, min_cpu, max_cpu, min_ram, max_ram, persistent_home, external_pvc
        )

        try:
            # Save to database
            self.save_connection_to_database(
                name,
                current_user.username,
                vnc_password,
                f"{settings.NAMESPACE}-{name}.dyn.cloud.e-infra.cz",
                "5900",
                persistent_home,
                desktop_configuration_id,
                external_pvc,
                session,
            )

            # Return connection details
            return {
                "name": name,
                "created_by": current_user.username,
                "is_stopped": False,
                "persistent_home": persistent_home,
                "desktop_configuration_id": desktop_configuration_id,
                "status": status,
                "external_pvc": external_pvc,  # Include PVC info in response
            }

        except Exception as e:
            # Clean up Rancher deployment if an error occurred after it was created
            try:
                rancher_client.uninstall(name)
                logging.debug("Cleaned up Rancher deployment after error")
            except Exception as cleanup_error:
                logging.error("Failed to clean up Rancher deployment: %s", str(cleanup_error))
            raise e

    def scale_down(self, connection_name, current_user, session):
        """Scale down a desktop connection."""
        logging.debug("Processing scale down for connection: %s", connection_name)

        conn_repo = ConnectionRepository(session)
        connection = conn_repo.get_by_name(connection_name)

        if not connection:
            raise NotFoundError(f"Connection {connection_name} not found")

        # Check if user has permission to delete this connection
        if not current_user.is_admin and connection.created_by != current_user.username:
            raise ForbiddenError("You do not have permission to delete this connection")

        # Get Guacamole connection ID
        persistent_home = connection.persistent_home

        rancher_client = client_factory.get_rancher_client()
        logging.debug("Created Rancher client for uninstallation")

        # Uninstall the Helm chart
        rancher_client.uninstall(connection.name)
        release_uninstalled = rancher_client.check_release_uninstalled(connection.name)
        if not release_uninstalled:
            logging.error("Failed to uninstall Rancher deployment")
            raise APIError(f"Failed to uninstall Rancher deployment for {connection.name}")

        logging.debug("Uninstalled Helm chart for %s", connection.name)

        # Check if we should soft delete or hard delete
        if persistent_home:
            # Soft delete - mark as stopped in the database
            conn_repo = ConnectionRepository(session)
            conn_repo.update_connection(connection.id, {"is_stopped": True})
            logging.debug("Marked connection as stopped: %s", connection_name)

            return {"message": f"Connection {connection_name} scaled down and preserved for future resumption"}
        else:
            # Hard delete - remove from database
            conn_repo = ConnectionRepository(session)
            conn_repo.delete_connection(connection.id)
            logging.debug("Hard deleted connection: %s", connection_name)

            return {"message": f"Connection {connection_name} permanently deleted"}

    def list_connections(self, current_user, creator_filter=None, session=None):
        """List all connections for the current user."""
        GuacamoleJsonAuth()
        get_settings()

        conn_repo = ConnectionRepository(session)
        if current_user.is_admin:
            if creator_filter:
                connections = conn_repo.get_connections_by_creator(creator_filter)
            else:
                connections = conn_repo.get_all_connections()
        else:
            connections = conn_repo.get_connections_by_creator(current_user.username)

        result = []

        for connection in connections:
            # Check if the connection has attached PVCs and get the name of the first one
            external_pvc = None
            if connection.pvcs and len(connection.pvcs) > 0:
                external_pvc = connection.pvcs[0].name

            # Add to result
            result.append(
                {
                    "id": connection.id,
                    "name": connection.name,
                    "created_at": (connection.created_at.isoformat() if connection.created_at else None),
                    "created_by": connection.created_by,
                    "persistent_home": connection.persistent_home,
                    "is_stopped": connection.is_stopped,
                    "desktop_configuration_id": connection.desktop_configuration_id,
                    "desktop_configuration_name": connection.desktop_configuration.name
                    if connection.desktop_configuration
                    else None,
                    "external_pvc": external_pvc,  # Include the external PVC name
                }
            )

        return {"connections": result}

    def get_connection(self, connection_name, current_user, session):
        """Get a connection by name."""
        conn_repo = ConnectionRepository(session)
        connection = conn_repo.get_by_name(connection_name)

        if not connection:
            raise NotFoundError("Connection not found")

        # Check if user has permission to access this connection
        if not current_user.is_admin and connection.created_by != current_user.username:
            raise ForbiddenError("You do not have permission to access this connection")

        return {
            "connection": {
                "name": connection.name,
                "created_at": connection.created_at.isoformat() if connection.created_at else None,
                "created_by": connection.created_by,
                "guacamole_connection_id": connection.guacamole_connection_id,
                "persistent_home": connection.persistent_home,
                "is_stopped": connection.is_stopped,
                "desktop_configuration_id": connection.desktop_configuration_id,
                "desktop_configuration_name": connection.desktop_configuration.name
                if connection.desktop_configuration
                else None,
            }
        }

    def direct_connect(self, connection_id, current_user, session):
        """Get the Guacamole auth URL for a direct connection."""
        conn_repo = ConnectionRepository(session)
        connection = conn_repo.get_by_id(connection_id)

        if not connection:
            raise NotFoundError("Connection not found")

        # Check if user has permission to access this connection
        if not current_user.is_admin and connection.created_by != current_user.username:
            raise ForbiddenError("You do not have permission to access this connection")

        # Generate auth token directly for this specific connection
        settings = get_settings()
        guacamole_json_auth = GuacamoleJsonAuth()
        guacamole_external_url = settings.EXTERNAL_GUACAMOLE_URL.rstrip("/")
        if not guacamole_external_url:
            guacamole_external_url = "http://localhost:8080/guacamole"

        guacamole_client = client_factory.get_guacamole_client()

        connection_params = GuacamoleConnectionParameters(
            hostname=connection.hostname,
            port=connection.port,
            password=decrypt_password(connection.encrypted_password),
        )

        token = guacamole_json_auth.generate_auth_data(
            username=current_user.username + "-tmp" + uuid.uuid4().hex,
            connections={
                connection.name + "-direct": {
                    "protocol": "vnc",
                    "parameters": connection_params.model_dump(),
                }
            },
            expires_in_ms=3600000,
        )  # 1 hour

        token = guacamole_client.json_auth_login(token)

        direct_url = f"{guacamole_external_url}/#/?token={token}"

        # Return the auth URL in the response
        return {
            "auth_url": direct_url,
            "connection_id": connection_id,
            "connection_name": connection.name,
        }

    def resume_connection(self, connection_name, current_user, session):
        """Resume a previously stopped connection."""
        settings = get_settings()
        logging.debug("Resuming connection: %s", connection_name)

        # Get connection from database
        conn_repo = ConnectionRepository(session)
        connection = conn_repo.get_by_name(connection_name)
        if not connection:
            raise NotFoundError(f"Stopped connection {connection_name} not found")

        # Check if user has permission to resume this connection
        if not current_user.is_admin and connection.created_by != current_user.username:
            raise ForbiddenError("You do not have permission to resume this connection")

        # Generate new VNC password
        vnc_password = generate_random_string(32)
        logging.debug("Generated VNC password")

        # Create Rancher API client
        get_settings()
        rancher_client = client_factory.get_rancher_client()
        logging.debug("Created Rancher client")

        external_pvc = connection.pvcs[0].name if connection.pvcs else None
        desktop_image, min_cpu, max_cpu, min_ram, max_ram, desktop_configuration_id = self.get_desktop_configuration(
            connection.desktop_configuration_id, current_user, session
        )
        desktop_values = DesktopValues(
            desktop=desktop_image,
            name=connection_name,
            vnc_password=vnc_password,
            mincpu=min_cpu,
            maxcpu=max_cpu,
            minram=min_ram,
            maxram=max_ram,
            external_pvc=external_pvc,  # Set external PVC if found
            guacamole={
                "namespace": settings.NAMESPACE,
                "releaseName": settings.GUACAMOLE_RELEASE_NAME,
            }
            if not settings.DEBUG
            else None,
        )

        # Configure storage with persistent_home setting
        desktop_values.storage.persistenthome = connection.persistent_home

        try:
            # Install Helm chart
            logging.debug("Installing Helm chart for %s", connection_name)
            rancher_client.install(connection_name, desktop_values)
            logging.debug("Helm chart installation completed")

            # Check if VNC server is ready
            logging.debug("Checking if VNC server is ready for %s", connection_name)
            vnc_ready = rancher_client.check_vnc_ready(connection_name)
            status = "ready" if vnc_ready else "provisioning"
            logging.debug("VNC server ready status for %s: %s", connection_name, status)

            # Update database to mark as active and update the new Guacamole connection ID
            conn_repo.update_connection(
                connection.id,
                {
                    "is_stopped": False,
                    "hostname": connection.hostname,
                    "port": connection.port,
                    "vnc_password": vnc_password,
                },
            )

            updated_connection = conn_repo.get_by_name(connection_name)
            logging.debug("Resumed connection in database: %s", connection_name)

            return {
                "message": f"Connection {connection_name} resumed successfully",
                "connection": {
                    "name": updated_connection.name,
                    "id": updated_connection.id,
                    "created_at": (
                        updated_connection.created_at.isoformat() if updated_connection.created_at else None
                    ),
                    "created_by": updated_connection.created_by,
                    "status": status,
                    "persistent_home": updated_connection.persistent_home,
                },
            }
        except Exception as e:
            logging.error("Error resuming connection: %s", str(e))
            raise APIError(f"Failed to resume connection: {e!s}") from e

    def permanent_delete(self, connection_name, current_user, session):
        """Permanently delete a connection and its associated PVC."""
        logging.debug("Permanently deleting connection: %s", connection_name)

        # Get connection from database
        conn_repo = ConnectionRepository(session)
        connection = conn_repo.get_by_name(connection_name)

        if not connection:
            raise NotFoundError(f"Connection {connection_name} not found")

        # Check if connection is stopped
        if not connection.is_stopped:
            raise BadRequestError(f"Connection {connection_name} must be stopped first")

        # Check if user has permission to delete this connection
        if not current_user.is_admin and connection.created_by != current_user.username:
            raise ForbiddenError("You do not have permission to delete this connection")

        # Delete the associated PVC if exists (format is [connection_name]-home)
        pvc_name = f"{connection_name}-home"
        rancher_client = client_factory.get_rancher_client()
        pvc_deleted = False

        try:
            # Try to get the PVC first to check if it exists
            rancher_client.get_pvc(name=pvc_name)

            # If no exception was raised, the PVC exists, so delete it
            rancher_client.delete_pvc(name=pvc_name)
            logging.debug("Deleted PVC: %s", pvc_name)
            pvc_deleted = True
        except Exception as e:
            logging.warning("Failed to delete PVC %s: %s", pvc_name, str(e))

        # Delete connection from database
        conn_repo.delete_connection(connection.id)
        logging.debug("Permanently deleted connection: %s", connection_name)

        # Return result
        message = f"Connection {connection_name} permanently deleted"
        if pvc_deleted:
            message += f" and PVC {pvc_name} removed"
        else:
            message += f" but failed to delete PVC {pvc_name}"

        return {"message": message}

    def attach_pvc_to_connection(self, connection_id, pvc_id, current_user, session):
        """Attach a PVC to a connection."""
        pvc_repo = StoragePVCRepository(session)
        if not current_user.is_admin and int(pvc_id) not in [
            pvc.id for pvc in pvc_repo.get_pvcs_for_user(current_user.username)
        ]:
            raise ForbiddenError("You do not have permission to attach this PVC to this connection")

        conn_repo = ConnectionRepository(session)
        connection = conn_repo.get_by_id(connection_id)
        restart = False

        if not connection.is_stopped:
            restart = True
            self.scale_down(connection.name, current_user, session)

        conn_repo.attach_pvc_to_connection(connection_id, pvc_id)

        if restart:
            self.resume_connection(connection.name, current_user, session)

    def detach_pvc_from_connection(self, connection_id, current_user, session):
        """Detach a PVC from a connection."""
        conn_repo = ConnectionRepository(session)
        connection = conn_repo.get_by_id(connection_id)
        restart = False

        if not connection.is_stopped:
            restart = True
            self.scale_down(connection.name, current_user, session)

        conn_repo.detach_pvc_from_connection(connection_id)

        if restart:
            self.resume_connection(connection.name, current_user, session)
