"""Connections client for API interactions."""

from typing import Any, Dict, List, Optional

from .base import APIError, BaseClient, ClientRequest


class ConnectionsClient(BaseClient):
    """Client for connection-related API interactions."""

    def list_connections(
        self,
        created_by: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get list of connections.

        Returns:
            List[Dict[str, Any]]: List of connections

        Raises:
            APIError: If request fails
        """

        params = {}
        if created_by:
            params["created_by"] = created_by

        try:
            endpoint = "/api/connections/list"

            data, _ = self.get(
                ClientRequest(
                    endpoint=endpoint,
                    params=params,
                    timeout=10,
                )
            )

            connections = data.get("connections", [])

            return connections
        except APIError as e:
            self.logger.error(f"Error fetching connections: {str(e)}")
            raise

    def add_connection(
        self,
        name: str,
        persistent_home: bool = True,
        desktop_configuration_id: Optional[int] = None,
        external_pvc: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Add a new connection.

        Args:
            name: Connection name
            persistent_home: Whether the home directory should be persistent. Default is True.
            desktop_configuration_id: Optional ID of the desktop configuration to use.
            external_pvc: Optional name of external PVC to use.

        Returns:
            Dict[str, Any]: Response data

        Raises:
            APIError: If request fails
        """

        payload = {
            "name": name,
            "persistent_home": persistent_home,
        }

        if desktop_configuration_id is not None:
            payload["desktop_configuration_id"] = desktop_configuration_id

        if external_pvc is not None:
            payload["external_pvc"] = external_pvc

        try:
            data, _ = self.post(
                ClientRequest(
                    endpoint="/api/connections/scaleup",
                    data=payload,
                    timeout=180,
                )
            )
            return data
        except APIError as e:
            self.logger.error(f"Error adding connection: {str(e)}")
            raise

    def stop_connection(self, name: str) -> Dict[str, Any]:
        """Stop a connection.

        Args:
            name: Connection name

        Returns:
            Dict[str, Any]: Response data

        Raises:
            APIError: If request fails
        """

        try:
            data, _ = self.post(
                ClientRequest(
                    endpoint="/api/connections/scaledown",
                    data={"name": name},
                    timeout=30,
                )
            )
            return data
        except APIError as e:
            self.logger.error(f"Error deleting connection: {str(e)}")
            raise

    def get_connection(self, name: str) -> Dict[str, Any]:
        """Get connection details.

        Args:
            name: Connection name

        Returns:
            Dict[str, Any]: Connection details

        Raises:
            APIError: If request fails
        """

        try:
            data, _ = self.get(
                ClientRequest(
                    endpoint=f"/api/connections/{name}",
                    timeout=10,
                )
            )
            return data.get("connection", {})
        except APIError as e:
            self.logger.error(f"Error fetching connection details: {str(e)}")
            raise

    def resume_connection(self, name: str) -> Dict[str, Any]:
        """Resume a stopped connection.

        Args:
            name: Connection name

        Returns:
            Dict[str, Any]: Response data

        Raises:
            APIError: If request fails
        """

        try:
            data, _ = self.post(
                ClientRequest(
                    endpoint="/api/connections/resume",
                    data={"name": name},
                    timeout=60,
                )
            )
            return data
        except APIError as e:
            self.logger.error(f"Error resuming connection: {str(e)}")
            raise

    def delete_connection(self, name: str) -> Dict[str, Any]:
        """Delete a connection.

        Args:
            name: Connection name

        Returns:
            Dict[str, Any]: Response data

        Raises:
            APIError: If request fails
        """

        try:
            data, _ = self.post(
                ClientRequest(
                    endpoint="/api/connections/permanent-delete",
                    data={"name": name},
                    timeout=30,
                )
            )
            return data
        except APIError as e:
            self.logger.error(f"Error permanently deleting connection: {str(e)}")
            raise

    def direct_connect(self, connection_id: str) -> Dict[str, Any]:
        """Direct connect to a connection.

        Args:
            connection_id: Connection ID

        Returns:
            Dict[str, Any]: Response data

        Raises:
            APIError: If request fails
        """
        try:
            data, _ = self.get(
                ClientRequest(
                    endpoint=f"/api/connections/direct-connect/{connection_id}",
                    timeout=10,
                )
            )
            return data
        except APIError as e:
            self.logger.error(f"Error direct connecting to connection: {str(e)}")
            raise

    def guacamole_dashboard(self) -> Dict[str, Any]:
        """Get the Guacamole dashboard auth URL.

        Returns:
            Dict[str, Any]: Response data
        """
        try:
            data, _ = self.get(
                ClientRequest(
                    endpoint="/api/connections/guacamole-dashboard",
                    timeout=10,
                )
            )
            return data
        except APIError as e:
            self.logger.error(f"Error getting Guacamole dashboard auth URL: {str(e)}")
            raise
