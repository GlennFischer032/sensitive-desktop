"""Client for interacting with desktop configurations API."""
import logging

from app.clients.base import APIError, BaseClient, ClientRequest

logger = logging.getLogger(__name__)


class DesktopConfigurationsClient(BaseClient):
    """Client for interacting with desktop configurations API."""

    def list_configurations(self) -> list[dict]:
        """List all desktop configurations.

        Returns:
            List[Dict]: List of desktop configurations

        Raises:
            APIError: If request fails
        """

        try:
            request = ClientRequest(
                endpoint="/api/desktop-config/list",
                timeout=10,
            )
            data, _ = self.get(request=request)
            return data.get("configurations", [])
        except APIError as e:
            logger.error(f"Error listing configurations: {str(e)}")
            raise

    def create_configuration(
        self,
        config_data: dict,
    ) -> dict:
        """Create a new desktop configuration.

        Args:
            config_data: Configuration data including name, description, image, CPU, RAM, etc.

        Returns:
            Dict: Created configuration data

        Raises:
            APIError: If request fails
        """

        try:
            request = ClientRequest(
                endpoint="/api/desktop-config/create",
                data=config_data,
                timeout=30,
            )
            data, _ = self.post(request=request)
            return data
        except APIError as e:
            logger.error(f"Error creating configuration: {str(e)}")
            raise

    def update_configuration(
        self,
        config_id: int,
        config_data: dict,
    ) -> dict:
        """Update an existing desktop configuration.

        Args:
            config_id: ID of the configuration to update
            config_data: Updated configuration data

        Returns:
            Dict: Updated configuration data

        Raises:
            APIError: If request fails
        """

        try:
            request = ClientRequest(
                endpoint=f"/api/desktop-config/update/{config_id}",
                data=config_data,
                timeout=30,
            )
            data, _ = self.put(request=request)
            return data
        except APIError as e:
            logger.error(f"Error updating configuration {config_id}: {str(e)}")
            raise

    def get_configuration(
        self,
        config_id: int,
    ) -> dict:
        """Get a specific desktop configuration.

        Args:
            config_id: ID of the configuration to get

        Returns:
            Dict: Configuration data

        Raises:
            APIError: If request fails
        """

        try:
            request = ClientRequest(
                endpoint=f"/api/desktop-config/get/{config_id}",
                timeout=10,
            )
            data, _ = self.get(request=request)
            return data
        except APIError as e:
            logger.error(f"Error getting configuration {config_id}: {str(e)}")
            raise

    def delete_configuration(
        self,
        config_id: int,
    ) -> dict:
        """Delete a desktop configuration.

        Args:
            config_id: ID of the configuration to delete

        Returns:
            Dict: Response data

        Raises:
            APIError: If request fails
        """

        try:
            request = ClientRequest(
                endpoint=f"/api/desktop-config/delete/{config_id}",
                timeout=30,
            )
            data, _ = self.delete(request=request)
            return data
        except APIError as e:
            logger.error(f"Error deleting configuration {config_id}: {str(e)}")
            raise

    def get_users(self) -> dict:
        """Get list of users for configuration access control.

        Returns:
            Dict: Users data

        Raises:
            APIError: If request fails
        """

        try:
            request = ClientRequest(
                endpoint="/api/users/list",
                timeout=10,
            )
            data, _ = self.get(request=request)
            return {"data": data.get("users", [])}
        except APIError as e:
            logger.error(f"Error getting users: {str(e)}")
            raise

    def get_configuration_users(
        self,
        config_id: int,
    ) -> dict:
        """Get users with access to a specific configuration.

        Args:
            config_id: ID of the configuration

        Returns:
            Dict: Users data with access to the configuration

        Raises:
            APIError: If request fails
        """

        try:
            request = ClientRequest(
                endpoint=f"/api/desktop-config/access/{config_id}",
                timeout=10,
            )
            data, _ = self.get(request=request)
            return {"data": data.get("users", [])}
        except APIError as e:
            logger.error(f"Error getting configuration users for {config_id}: {str(e)}")
            raise

    def get_connections(self) -> dict:
        """Get connections for identifying which ones use a configuration.

        Returns:
            Dict: Connections data

        Raises:
            APIError: If request fails
        """

        try:
            request = ClientRequest(
                endpoint="/api/connections/list",
                timeout=10,
            )
            data, _ = self.get(request=request)
            return {"data": data.get("connections", [])}
        except APIError as e:
            logger.error(f"Error getting connections: {str(e)}")
            raise
