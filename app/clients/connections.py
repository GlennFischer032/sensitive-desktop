"""Connections client for API interactions."""

from typing import Any, Dict, List, Optional

from flask import session

from .base import APIError, BaseClient


class ConnectionsClient(BaseClient):
    """Client for connection-related API interactions."""

    def list_connections(
        self, token: Optional[str] = None, filter_by_user: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get list of connections.

        Args:
            token: Authentication token. If None, uses token from session.
            filter_by_user: Optional username to filter connections created by this user.

        Returns:
            List[Dict[str, Any]]: List of connections

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            self.logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        try:
            endpoint = "/api/connections/list"
            params = {}

            # Try to use server-side filtering if supported
            if filter_by_user:
                params["created_by"] = filter_by_user

            data, _ = self.get(
                endpoint=endpoint,
                params=params,
                token=token,
                timeout=10,
            )

            connections = data.get("connections", [])

            # Always perform client-side filtering if filter_by_user is specified
            # This ensures proper filtering even if the API doesn't support it
            if filter_by_user:
                self.logger.debug(f"Filtering connections for user: {filter_by_user}")
                connections = [
                    conn for conn in connections if conn.get("created_by") == filter_by_user
                ]
                self.logger.debug(f"Found {len(connections)} connections for user {filter_by_user}")

            return connections
        except APIError as e:
            self.logger.error(f"Error fetching connections: {str(e)}")
            raise

    def add_connection(
        self,
        name: str,
        token: Optional[str] = None,
        persistent_home: bool = True,
        desktop_configuration_id: Optional[int] = None,
        min_cpu: Optional[int] = None,
        max_cpu: Optional[int] = None,
        min_ram: Optional[str] = None,
        max_ram: Optional[str] = None,
        external_pvc: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Add a new connection.

        Args:
            name: Connection name
            token: Authentication token. If None, uses token from session.
            persistent_home: Whether the home directory should be persistent. Default is True.
            desktop_configuration_id: Optional ID of the desktop configuration to use.
            min_cpu: Optional minimum number of CPU cores.
            max_cpu: Optional maximum number of CPU cores.
            min_ram: Optional minimum RAM allocation.
            max_ram: Optional maximum RAM allocation.
            external_pvc: Optional name of external PVC to use.

        Returns:
            Dict[str, Any]: Response data

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            self.logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        payload = {
            "name": name,
            "persistent_home": persistent_home,
        }

        if desktop_configuration_id is not None:
            payload["desktop_configuration_id"] = desktop_configuration_id

        if min_cpu is not None:
            payload["min_cpu"] = min_cpu

        if max_cpu is not None:
            payload["max_cpu"] = max_cpu

        if min_ram is not None:
            payload["min_ram"] = min_ram

        if max_ram is not None:
            payload["max_ram"] = max_ram

        if external_pvc is not None:
            payload["external_pvc"] = external_pvc

        try:
            data, _ = self.post(
                endpoint="/api/connections/scaleup",
                data=payload,
                token=token,
                timeout=180,
            )
            return data
        except APIError as e:
            self.logger.error(f"Error adding connection: {str(e)}")
            raise

    def delete_connection(self, name: str, token: Optional[str] = None) -> Dict[str, Any]:
        """Delete a connection.

        Args:
            name: Connection name
            token: Authentication token. If None, uses token from session.

        Returns:
            Dict[str, Any]: Response data

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            self.logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        try:
            data, _ = self.post(
                endpoint="/api/connections/scaledown",
                data={"name": name},
                token=token,
                timeout=30,
            )
            return data
        except APIError as e:
            self.logger.error(f"Error deleting connection: {str(e)}")
            raise

    def get_connection(self, name: str, token: Optional[str] = None) -> Dict[str, Any]:
        """Get connection details.

        Args:
            name: Connection name
            token: Authentication token. If None, uses token from session.

        Returns:
            Dict[str, Any]: Connection details

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            self.logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        try:
            data, _ = self.get(
                endpoint=f"/api/connections/{name}",
                token=token,
                timeout=10,
            )
            return data.get("connection", {})
        except APIError as e:
            self.logger.error(f"Error fetching connection details: {str(e)}")
            raise

    def resume_connection(self, name: str, token: Optional[str] = None) -> Dict[str, Any]:
        """Resume a stopped connection.

        Args:
            name: Connection name
            token: Authentication token. If None, uses token from session.

        Returns:
            Dict[str, Any]: Response data

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            self.logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        try:
            data, _ = self.post(
                endpoint="/api/connections/resume",
                data={"name": name},
                token=token,
                timeout=60,
            )
            return data
        except APIError as e:
            self.logger.error(f"Error resuming connection: {str(e)}")
            raise

    def permanent_delete_connection(self, name: str, token: Optional[str] = None) -> Dict[str, Any]:
        """Permanently delete a stopped connection and its PVC.

        Args:
            name: Connection name
            token: Authentication token. If None, uses token from session.

        Returns:
            Dict[str, Any]: Response data

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            self.logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        try:
            data, _ = self.post(
                endpoint="/api/connections/permanent-delete",
                data={"name": name},
                token=token,
                timeout=30,
            )
            return data
        except APIError as e:
            self.logger.error(f"Error permanently deleting connection: {str(e)}")
            raise
