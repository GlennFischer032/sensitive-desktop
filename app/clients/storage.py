"""Storage client for API interactions."""

from typing import Any, Dict, List, Optional


from .base import APIError, BaseClient, ClientRequest


class StorageClient(BaseClient):
    """Client for storage-related API interactions."""

    def list_storage(self) -> List[Dict[str, Any]]:
        """Get list of storage volumes.

        Returns:
            List[Dict[str, Any]]: List of storage volumes

        Raises:
            APIError: If request fails
        """

        try:
            request = ClientRequest(
                endpoint="/api/storage-pvcs/list",
            )
            data, _ = self.get(request=request)
            return data.get("pvcs", [])
        except APIError as e:
            self.logger.error(f"Error fetching storage volumes: {str(e)}")
            raise

    def get_storage(self, volume_id: str) -> Dict[str, Any]:
        """Get storage volume details.

        Args:
            volume_id: Volume identifier

        Returns:
            Dict[str, Any]: Volume details

        Raises:
            APIError: If request fails
        """

        try:
            request = ClientRequest(
                endpoint=f"/api/storage-pvcs/{volume_id}",
            )
            data, _ = self.get(request=request)
            return data.get("pvc", {})
        except APIError as e:
            self.logger.error(f"Error fetching storage volume details: {str(e)}")
            raise

    def create_storage(
        self,
        name: str,
        size: str,
        is_public: bool = False,
        allowed_users: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Create a new storage volume.

        Args:
            name: Volume name
            size: Volume size (e.g., "10Gi")
            is_public: Whether the volume is publicly available
            allowed_users: List of usernames with access (if not public)

        Returns:
            Dict[str, Any]: Response data

        Raises:
            APIError: If request fails
        """

        payload = {
            "name": name,
            "size": size,
            "is_public": is_public,
        }

        if allowed_users:
            payload["allowed_users"] = allowed_users

        try:
            request = ClientRequest(
                endpoint="/api/storage-pvcs/create",
                data=payload,
                timeout=30,
            )
            data, _ = self.post(request=request)
            return data
        except APIError as e:
            self.logger.error(f"Error creating storage volume: {str(e)}")
            raise

    def delete_storage(self, volume_id: str) -> Dict[str, Any]:
        """Delete a storage volume.

        Args:
            volume_id: Volume identifier

        Returns:
            Dict[str, Any]: Response data

        Raises:
            APIError: If request fails
        """

        try:
            request = ClientRequest(
                endpoint=f"/api/storage-pvcs/{volume_id}",
                timeout=30,
            )
            data, _ = self.delete(request=request)
            return data
        except APIError as e:
            self.logger.error(f"Error deleting storage volume: {str(e)}")
            raise

    def get_pvc_access(self, pvc_id: int) -> Dict[str, Any]:
        """Get access information for a storage PVC.

        Args:
            pvc_id: PVC ID

        Returns:
            Dict[str, Any]: Access information with list of users

        Raises:
            APIError: If request fails
        """

        try:
            request = ClientRequest(
                endpoint=f"/api/storage-pvcs/{pvc_id}/access",
                timeout=10,
            )
            data, _ = self.get(request=request)
            return data
        except APIError as e:
            self.logger.error(f"Error fetching PVC access information: {str(e)}")
            raise

    def update_pvc_access(self, pvc_id: int, is_public: bool, allowed_users: List[str]) -> Dict[str, Any]:
        """Update access settings for a storage PVC.

        Args:
            pvc_id: PVC ID
            is_public: Whether the PVC is publicly available
            allowed_users: List of usernames with access (if not public)

        Returns:
            Dict[str, Any]: Response data

        Raises:
            APIError: If request fails
        """

        payload = {
            "is_public": is_public,
            "allowed_users": allowed_users,
        }

        try:
            request = ClientRequest(
                endpoint=f"/api/storage-pvcs/{pvc_id}/access",
                data=payload,
                timeout=30,
            )
            data, _ = self.post(request=request)
            return data
        except APIError as e:
            self.logger.error(f"Error updating PVC access: {str(e)}")
            raise

    def get_pvc_connections(self, pvc_id: int) -> Dict[str, Any]:
        """Get connections using a specific PVC.

        Args:
            pvc_id: PVC ID

        Returns:
            Dict[str, Any]: Response data

        Raises:
            APIError: If request fails
        """

        try:
            request = ClientRequest(
                endpoint=f"/api/storage-pvcs/connections/{pvc_id}",
                timeout=10,
            )
            data, _ = self.get(request=request)
            return data
        except APIError as e:
            self.logger.error(f"Error fetching PVC connections: {str(e)}")
            raise
