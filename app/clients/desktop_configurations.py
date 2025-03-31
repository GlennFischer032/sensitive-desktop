"""Client for interacting with desktop configurations API."""
import logging
from typing import Dict, List, Optional

from flask import session

from app.clients.base import APIError, BaseClient

logger = logging.getLogger(__name__)


class DesktopConfigurationsClient(BaseClient):
    """Client for interacting with desktop configurations API."""

    def list_configurations(self, token: Optional[str] = None) -> List[Dict]:
        """List all desktop configurations.

        Args:
            token: Authentication token. If None, uses token from session.

        Returns:
            List[Dict]: List of desktop configurations

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        try:
            data, _ = self.get(
                endpoint="/api/desktop-config/list",
                token=token,
                timeout=10,
            )
            return data.get("configurations", [])
        except APIError as e:
            logger.error(f"Error listing configurations: {str(e)}")
            raise

    def create_configuration(
        self,
        config_data: Dict,
        token: Optional[str] = None,
    ) -> Dict:
        """Create a new desktop configuration.

        Args:
            config_data: Configuration data including name, description, image, CPU, RAM, etc.
            token: Authentication token. If None, uses token from session.

        Returns:
            Dict: Created configuration data

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        try:
            data, _ = self.post(
                endpoint="/api/desktop-config/create",
                data=config_data,
                token=token,
                timeout=30,
            )
            return data
        except APIError as e:
            logger.error(f"Error creating configuration: {str(e)}")
            raise

    def update_configuration(
        self,
        config_id: int,
        config_data: Dict,
        token: Optional[str] = None,
    ) -> Dict:
        """Update an existing desktop configuration.

        Args:
            config_id: ID of the configuration to update
            config_data: Updated configuration data
            token: Authentication token. If None, uses token from session.

        Returns:
            Dict: Updated configuration data

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        try:
            data, _ = self.put(
                endpoint=f"/api/desktop-config/update/{config_id}",
                data=config_data,
                token=token,
                timeout=30,
            )
            return data
        except APIError as e:
            logger.error(f"Error updating configuration {config_id}: {str(e)}")
            raise

    def get_configuration(
        self,
        config_id: int,
        token: Optional[str] = None,
    ) -> Dict:
        """Get a specific desktop configuration.

        Args:
            config_id: ID of the configuration to get
            token: Authentication token. If None, uses token from session.

        Returns:
            Dict: Configuration data

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        try:
            data, _ = self.get(
                endpoint=f"/api/desktop-config/get/{config_id}",
                token=token,
                timeout=10,
            )
            return data
        except APIError as e:
            logger.error(f"Error getting configuration {config_id}: {str(e)}")
            raise

    def delete_configuration(
        self,
        config_id: int,
        token: Optional[str] = None,
    ) -> Dict:
        """Delete a desktop configuration.

        Args:
            config_id: ID of the configuration to delete
            token: Authentication token. If None, uses token from session.

        Returns:
            Dict: Response data

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        try:
            data, _ = self.delete(
                endpoint=f"/api/desktop-config/delete/{config_id}",
                token=token,
                timeout=30,
            )
            return data
        except APIError as e:
            logger.error(f"Error deleting configuration {config_id}: {str(e)}")
            raise

    def get_users(self, token: Optional[str] = None) -> Dict:
        """Get list of users for configuration access control.

        Args:
            token: Authentication token. If None, uses token from session.

        Returns:
            Dict: Users data

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        try:
            data, _ = self.get(
                endpoint="/api/users/list",
                token=token,
                timeout=10,
            )
            return {"data": data.get("users", [])}
        except APIError as e:
            logger.error(f"Error getting users: {str(e)}")
            raise

    def get_configuration_users(
        self,
        config_id: int,
        token: Optional[str] = None,
    ) -> Dict:
        """Get users with access to a specific configuration.

        Args:
            config_id: ID of the configuration
            token: Authentication token. If None, uses token from session.

        Returns:
            Dict: Users data with access to the configuration

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        try:
            data, _ = self.get(
                endpoint=f"/api/desktop-config/access/{config_id}",
                token=token,
                timeout=10,
            )
            return {"data": data.get("users", [])}
        except APIError as e:
            logger.error(f"Error getting configuration users for {config_id}: {str(e)}")
            raise

    def get_connections(self, token: Optional[str] = None) -> Dict:
        """Get connections for identifying which ones use a configuration.

        Args:
            token: Authentication token. If None, uses token from session.

        Returns:
            Dict: Connections data

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        try:
            data, _ = self.get(
                endpoint="/api/connections/list",
                token=token,
                timeout=10,
            )
            return {"data": data.get("connections", [])}
        except APIError as e:
            logger.error(f"Error getting connections: {str(e)}")
            raise
