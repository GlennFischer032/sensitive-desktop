"""Storage client for API interactions."""

from typing import Any, Dict, List, Optional, Tuple

from flask import session

from .base import APIError, BaseClient


class StorageClient(BaseClient):
    """Client for storage-related API interactions."""

    def list_storage(self, token: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get list of storage volumes.

        Args:
            token: Authentication token. If None, uses token from session.

        Returns:
            List[Dict[str, Any]]: List of storage volumes

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            self.logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        try:
            data, _ = self.get(
                endpoint="/api/storage/list",
                token=token,
                timeout=10,
            )
            return data.get("volumes", [])
        except APIError as e:
            self.logger.error(f"Error fetching storage volumes: {str(e)}")
            raise

    def get_storage(self, volume_id: str, token: Optional[str] = None) -> Dict[str, Any]:
        """Get storage volume details.

        Args:
            volume_id: Volume identifier
            token: Authentication token. If None, uses token from session.

        Returns:
            Dict[str, Any]: Volume details

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            self.logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        try:
            data, _ = self.get(
                endpoint=f"/api/storage/{volume_id}",
                token=token,
                timeout=10,
            )
            return data.get("volume", {})
        except APIError as e:
            self.logger.error(f"Error fetching storage volume details: {str(e)}")
            raise

    def create_storage(
        self,
        name: str,
        size: str,
        is_public: bool = False,
        allowed_users: Optional[List[str]] = None,
        token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new storage volume.

        Args:
            name: Volume name
            size: Volume size (e.g., "10Gi")
            is_public: Whether the volume is publicly available
            allowed_users: List of usernames with access (if not public)
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

        payload = {
            "name": name,
            "size": size,
            "is_public": is_public,
        }

        if allowed_users:
            payload["allowed_users"] = allowed_users

        try:
            data, _ = self.post(
                endpoint="/api/storage/create",
                data=payload,
                token=token,
                timeout=30,
            )
            return data
        except APIError as e:
            self.logger.error(f"Error creating storage volume: {str(e)}")
            raise

    def delete_storage(self, volume_id: str, token: Optional[str] = None) -> Dict[str, Any]:
        """Delete a storage volume.

        Args:
            volume_id: Volume identifier
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
            data, _ = self.delete(
                endpoint=f"/api/storage/delete/{volume_id}",
                token=token,
                timeout=30,
            )
            return data
        except APIError as e:
            self.logger.error(f"Error deleting storage volume: {str(e)}")
            raise

    def resize_storage(
        self, volume_id: str, new_size: str, token: Optional[str] = None
    ) -> Dict[str, Any]:
        """Resize a storage volume.

        Args:
            volume_id: Volume identifier
            new_size: New volume size (e.g., "20Gi")
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
            data, _ = self.put(
                endpoint=f"/api/storage/resize/{volume_id}",
                data={"size": new_size},
                token=token,
                timeout=30,
            )
            return data
        except APIError as e:
            self.logger.error(f"Error resizing storage volume: {str(e)}")
            raise

    def get_pvc_access(self, pvc_id: int, token: Optional[str] = None) -> Dict[str, Any]:
        """Get access information for a storage PVC.

        Args:
            pvc_id: PVC ID
            token: Authentication token. If None, uses token from session.

        Returns:
            Dict[str, Any]: Access information with list of users

        Raises:
            APIError: If request fails
        """
        token = token or session.get("token")
        if not token:
            self.logger.error("No authentication token available")
            raise APIError("Authentication required", status_code=401)

        try:
            data, _ = self.get(
                endpoint=f"/api/storage-pvcs/{pvc_id}/access",
                token=token,
                timeout=10,
            )
            return data
        except APIError as e:
            self.logger.error(f"Error fetching PVC access information: {str(e)}")
            raise

    def update_pvc_access(
        self, pvc_id: int, is_public: bool, allowed_users: List[str], token: Optional[str] = None
    ) -> Dict[str, Any]:
        """Update access settings for a storage PVC.

        Args:
            pvc_id: PVC ID
            is_public: Whether the PVC is publicly available
            allowed_users: List of usernames with access (if not public)
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

        payload = {
            "is_public": is_public,
            "allowed_users": allowed_users,
        }

        try:
            data, _ = self.post(
                endpoint=f"/api/storage-pvcs/{pvc_id}/access",
                data=payload,
                token=token,
                timeout=30,
            )
            return data
        except APIError as e:
            self.logger.error(f"Error updating PVC access: {str(e)}")
            raise

    def attach_storage(
        self, volume_id: str, connection_name: str, mount_path: str, token: Optional[str] = None
    ) -> Dict[str, Any]:
        """Attach a storage volume to a connection.

        Args:
            volume_id: Volume identifier
            connection_name: Name of the connection to attach to
            mount_path: Path to mount the volume at
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

        payload = {
            "volume_id": volume_id,
            "connection_name": connection_name,
            "mount_path": mount_path,
        }

        try:
            data, _ = self.post(
                endpoint="/api/storage/attach",
                data=payload,
                token=token,
                timeout=30,
            )
            return data
        except APIError as e:
            self.logger.error(f"Error attaching storage volume: {str(e)}")
            raise

    def detach_storage(
        self, volume_id: str, connection_name: str, token: Optional[str] = None
    ) -> Dict[str, Any]:
        """Detach a storage volume from a connection.

        Args:
            volume_id: Volume identifier
            connection_name: Name of the connection to detach from
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

        payload = {
            "volume_id": volume_id,
            "connection_name": connection_name,
        }

        try:
            data, _ = self.post(
                endpoint="/api/storage/detach",
                data=payload,
                token=token,
                timeout=30,
            )
            return data
        except APIError as e:
            self.logger.error(f"Error detaching storage volume: {str(e)}")
            raise
