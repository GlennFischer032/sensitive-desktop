import logging
from typing import Any

from clients.factory import client_factory
from config.settings import get_settings
from database.repositories.connection import ConnectionRepository
from database.repositories.storage_pvc import StoragePVCRepository
from schemas.storage_pvc import StoragePVC as StoragePVCModel
from services.connections import APIError, BadRequestError, NotFoundError


class StoragePVCService:
    """Service for managing storage PVCs."""

    def create_storage_pvc(self, data, current_user, session) -> dict[str, Any]:
        """Create a new storage PVC.

        Args:
            data: PVC data including name, size, and is_public flag
            current_user: Current authenticated user
            session: Database session

        Returns:
            Dictionary with created PVC details

        Raises:
            BadRequestError: If request data is invalid
            APIError: If an error occurs during processing
        """
        try:
            if not data:
                raise BadRequestError("No input data provided")

            # Extract and validate required fields
            name = data.get("name")
            size = data.get("size", "10Gi")
            is_public = data.get("is_public", False)

            if not name:
                raise BadRequestError("Missing required field: name")

            # Get settings and clients
            settings = get_settings()
            namespace = settings.NAMESPACE

            # Use the repository to check if PVC already exists
            pvc_repo = StoragePVCRepository(session)
            existing_pvc = pvc_repo.get_by_name(name)

            if existing_pvc:
                raise BadRequestError(f"PVC with name '{name}' already exists")

            # Create PVC in Kubernetes
            rancher_client = client_factory.get_rancher_client()
            logging.debug("Creating PVC '%s' in namespace '%s' with size '%s'", name, namespace, size)
            pvc_data = rancher_client.create_pvc(
                name=name,
                namespace=namespace,
                size=size,
            )
            logging.debug("PVC created successfully: %s", pvc_data)

            # Store PVC in database using repository
            pvc_db_data = {
                "name": name,
                "namespace": namespace,
                "size": size,
                "created_by": current_user.username,
                "status": "Pending",
                "is_public": is_public,
            }

            pvc = pvc_repo.create_storage_pvc(pvc_db_data)
            session.expunge(pvc)
            result = pvc.__dict__
            result.pop("_sa_instance_state", None)
            return {"message": "PVC created successfully", "pvc": result}
        except APIError:
            # Re-raise API errors
            raise
        except Exception as e:
            error_message = f"Failed to create PVC: {e!s}"
            logging.error(error_message)
            raise APIError(error_message) from e

    def list_storage_pvcs(self, current_user, session) -> dict[str, Any]:
        """List storage PVCs.

        Args:
            current_user: Current authenticated user
            session: Database session

        Returns:
            Dictionary with list of PVCs

        Raises:
            APIError: If an error occurs during processing
        """
        try:
            # Use repository to get PVCs from database
            pvc_repo = StoragePVCRepository(session)

            # Different handling for admins vs regular users
            if current_user.is_admin:
                pvcs = pvc_repo.get_pvcs_for_admin()
            else:
                # For regular users, only show accessible PVCs
                pvcs = pvc_repo.get_pvcs_for_user(current_user.username)

            # Get Rancher client to update PVC statuses
            rancher_client = client_factory.get_rancher_client()

            # Process the PVCs and add access information
            result = []
            for pvc in pvcs:
                # Check and update PVC status from Kubernetes
                try:
                    pvc_k8s_data = rancher_client.get_pvc(
                        name=pvc.name,
                        namespace=pvc.namespace,
                    )
                    # Update status if needed
                    k8s_status = pvc_k8s_data.get("status", {}).get("phase", "Unknown")
                    if k8s_status != pvc.status:
                        pvc_repo.update_storage_pvc(
                            pvc.id,
                            {"status": k8s_status},
                        )
                        pvc.status = k8s_status
                except Exception as e:
                    logging.warning("Failed to get PVC details from Rancher for %s: %s", pvc.name, str(e))
                    # Continue with database data

                # Get users with access to this PVC
                allowed_users = pvc_repo.get_pvc_users(pvc.id)

                # Convert to API model
                pvc_model = StoragePVCModel.model_validate(pvc)
                pvc_dict = pvc_model.model_dump()
                pvc_dict["allowed_users"] = allowed_users

                result.append(pvc_dict)

            return {"pvcs": result}
        except Exception as e:
            error_message = f"Failed to list PVCs: {e!s}"
            logging.error(error_message)
            raise APIError(error_message) from e

    def delete_storage_pvc(self, pvc_id, session) -> dict[str, Any]:
        """Delete a storage PVC.

        Args:
            pvc_id: PVC ID
            session: Database session

        Returns:
            Dictionary with deletion confirmation message

        Raises:
            NotFoundError: If PVC is not found
            BadRequestError: If PVC is in use
            APIError: If an error occurs during processing
        """
        try:
            # Use repository to get and delete PVC
            pvc_repo = StoragePVCRepository(session)

            # Get PVC from database
            pvc = pvc_repo.get_by_id(pvc_id)
            if not pvc:
                raise NotFoundError(f"PVC with ID {pvc_id} not found")

            # Check if PVC is being used by any connection
            if pvc_repo.is_pvc_in_use(pvc.id):
                raise BadRequestError("Cannot delete PVC that is in use by one or more connections")

            # Delete PVC from Kubernetes
            rancher_client = client_factory.get_rancher_client()
            try:
                rancher_client.delete_pvc(
                    name=pvc.name,
                    namespace=pvc.namespace,
                )
            except Exception as e:
                logging.warning("Failed to delete PVC from Kubernetes: %s", str(e))
                # Continue with database deletion

            # Delete PVC from database
            pvc_repo.delete_storage_pvc(pvc.id)

            return {"message": f"PVC '{pvc.name}' deleted successfully"}
        except APIError:
            # Re-raise API errors
            raise
        except Exception as e:
            error_message = f"Failed to delete PVC: {e!s}"
            logging.error(error_message)
            raise APIError(error_message) from e

    def get_pvc_access(self, pvc_id, session) -> dict[str, Any]:
        """Get users with access to a specific PVC.

        Args:
            pvc_id: PVC ID
            session: Database session

        Returns:
            Dictionary with list of users who have access

        Raises:
            APIError: If an error occurs during processing
        """
        try:
            # Get users with access
            pvc_repo = StoragePVCRepository(session)
            allowed_users = pvc_repo.get_pvc_users(pvc_id)

            return {"users": allowed_users}
        except Exception as e:
            error_message = f"Failed to get PVC access: {e!s}"
            logging.error(error_message)
            raise APIError(error_message) from e

    def update_pvc_access(self, pvc_id, data, session) -> dict[str, Any]:
        """Update access to a PVC.

        Args:
            pvc_id: PVC ID
            data: PVC access data including is_public flag and allowed_users list
            session: Database session

        Returns:
            Dictionary with update confirmation message

        Raises:
            BadRequestError: If request data is invalid
            NotFoundError: If PVC is not found
            APIError: If an error occurs during processing
        """
        try:
            # Parse input data
            if not data:
                raise BadRequestError("No input data provided")

            # Get is_public and allowed_users from data
            is_public = data.get("is_public", False)
            allowed_users = data.get("allowed_users", [])

            # Use repository to update PVC access
            pvc_repo = StoragePVCRepository(session)

            # Get the PVC to check ownership
            pvc = pvc_repo.get_by_id(pvc_id)
            if not pvc:
                raise NotFoundError(f"PVC with ID {pvc_id} not found")

            # Update is_public status
            pvc_repo.update_storage_pvc(pvc_id, {"is_public": is_public})

            # Clear existing access
            pvc_repo.clear_pvc_access(pvc_id)

            # Add new access if not public
            if not is_public and allowed_users:
                for username in allowed_users:
                    try:
                        pvc_repo.create_pvc_access(pvc_id, username)
                    except Exception as e:
                        logging.warning("Failed to add access for user %s: %s", username, str(e))

            return {"message": "PVC access updated successfully"}
        except APIError:
            # Re-raise API errors
            raise
        except Exception as e:
            error_message = f"Failed to update PVC access: {e!s}"
            logging.error(error_message)
            raise APIError(error_message) from e

    def get_storage_pvc_by_id(self, pvc_id, session) -> dict[str, Any]:
        """Get storage PVC details by ID.

        Args:
            pvc_id: PVC ID
            session: Database session

        Returns:
            Dictionary with PVC details

        Raises:
            NotFoundError: If PVC is not found
            APIError: If an error occurs during processing
        """
        try:
            # Use repository to get PVC
            pvc_repo = StoragePVCRepository(session)

            # Get PVC from database
            pvc = pvc_repo.get_by_id(pvc_id)
            if not pvc:
                raise NotFoundError(f"PVC with ID {pvc_id} not found")

            # Get PVC details from Rancher
            rancher_client = client_factory.get_rancher_client()
            try:
                pvc_k8s_data = rancher_client.get_pvc(
                    name=pvc.name,
                    namespace=pvc.namespace,
                )
                # Update status if needed
                k8s_status = pvc_k8s_data.get("status", {}).get("phase", "Unknown")
                if k8s_status != pvc.status:
                    pvc_repo.update_storage_pvc(
                        pvc.id,
                        {"status": k8s_status},
                    )
                    pvc.status = k8s_status
            except Exception as e:
                logging.warning("Failed to get PVC details from Rancher: %s", str(e))
                # Continue with database data

            # Get access information
            allowed_users = pvc_repo.get_pvc_users(pvc.id)

            # Convert to API model
            pvc_model = StoragePVCModel.model_validate(pvc)
            pvc_dict = pvc_model.model_dump()
            pvc_dict["allowed_users"] = allowed_users

            return {"pvc": pvc_dict}
        except APIError:
            # Re-raise API errors
            raise
        except Exception as e:
            error_message = f"Failed to get PVC details: {e!s}"
            logging.error(error_message)
            raise APIError(error_message) from e

    def get_pvc_connections(self, pvc_id, session) -> dict[str, Any]:
        """Get connections that are using a specific PVC.

        Args:
            pvc_id: PVC ID
            session: Database session

        Returns:
            Dictionary with list of connections

        Raises:
            APIError: If an error occurs during processing
        """
        try:
            conn_repo = ConnectionRepository(session)
            connections = conn_repo.get_connections_for_pvc(pvc_id)

            result = [
                {
                    "id": row.id,
                    "name": row.name,
                    "created_at": row.created_at.isoformat(),
                    "created_by": row.created_by,
                    "is_stopped": row.is_stopped,
                }
                for row in connections
            ]

            return {"connections": result}
        except Exception as e:
            error_message = f"Failed to get connections for PVC: {e!s}"
            logging.error(error_message)
            raise APIError(error_message) from e
