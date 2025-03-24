"""Connections client for API interactions."""

from typing import Any, Dict, List, Optional, Tuple

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

            if filter_by_user:
                params["created_by"] = filter_by_user

            data, _ = self.get(
                endpoint=endpoint,
                params=params,
                token=token,
                timeout=10,
            )

            connections = data.get("connections", [])

            # If filtering by user but the API doesn't support the filter parameter,
            # perform filtering client-side
            if filter_by_user and not params:
                connections = [
                    conn for conn in connections if conn.get("created_by") == filter_by_user
                ]

            return connections
        except APIError as e:
            self.logger.error(f"Error fetching connections: {str(e)}")
            raise

    def add_connection(self, name: str, token: Optional[str] = None) -> Dict[str, Any]:
        """Add a new connection.

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
                endpoint="/api/connections/scaleup",
                data={"name": name},
                token=token,
                timeout=30,
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
