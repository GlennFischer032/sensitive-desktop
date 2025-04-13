"""Storage PVC routes module for desktop-manager-api.

This module provides API routes for managing Persistent Volume Claims (PVCs).
"""

from http import HTTPStatus
import logging
from typing import Any

from clients.factory import client_factory
from config.settings import get_settings
from core.auth import admin_required, token_required
from database.core.session import get_db_session
from database.repositories.connection import ConnectionRepository
from database.repositories.storage_pvc import StoragePVCRepository
from flask import Blueprint, jsonify, request
from schemas.storage_pvc import (
    StoragePVC as StoragePVCModel,
)


storage_pvc_bp = Blueprint("storage_pvc_bp", __name__)


@storage_pvc_bp.route("/create", methods=["POST"])
@token_required
@admin_required
def create_storage_pvc() -> tuple[dict[str, Any], int]:
    """Create a new storage PVC.

    This endpoint creates a new Persistent Volume Claim (PVC) by:
    1. Validating the input data
    2. Creating a PVC via Rancher API
    3. Storing the PVC details in the database

    Returns:
        Tuple[Dict[str, Any], int]: Response data and status code
    """
    logging.info("=== Received request to create a storage PVC ===")

    try:
        current_user = request.current_user
        # Parse and validate input data
        data = request.get_json()
        if not data:
            return (
                jsonify({"error": "No input data provided"}),
                HTTPStatus.BAD_REQUEST,
            )

        # Extract and validate required fields
        name = data.get("name")
        size = data.get("size", "10Gi")
        is_public = data.get("is_public", False)

        if not name:
            return (
                jsonify({"error": "Missing required field: name"}),
                HTTPStatus.BAD_REQUEST,
            )

        # Get settings and clients
        settings = get_settings()
        namespace = settings.NAMESPACE

        # Use the repository to check if PVC already exists
        with get_db_session() as session:
            pvc_repo = StoragePVCRepository(session)
            existing_pvc = pvc_repo.get_by_name(name)

            if existing_pvc:
                return (
                    jsonify({"error": f"PVC with name '{name}' already exists"}),
                    HTTPStatus.CONFLICT,
                )

            # Create PVC in Kubernetes
            rancher_client = client_factory.get_rancher_client()
            logging.info("Creating PVC '%s' in namespace '%s' with size '%s'", name, namespace, size)
            pvc_data = rancher_client.create_pvc(
                name=name,
                namespace=namespace,
                size=size,
            )
            logging.info("PVC created successfully: %s", pvc_data)

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
            res = pvc.__dict__
            res.pop("_sa_instance_state", None)
            return (
                jsonify({"message": "PVC created successfully", "pvc": pvc.__dict__}),
                HTTPStatus.CREATED,
            )
    except Exception as e:
        error_message = f"Failed to create PVC: {e!s}"
        logging.error(error_message)
        return (
            jsonify({"error": error_message}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@storage_pvc_bp.route("/list", methods=["GET"])
@token_required
def list_storage_pvcs() -> tuple[dict[str, Any], int]:
    """List storage PVCs.

    Returns:
        Tuple[Dict[str, Any], int]: Response data and status code
    """
    try:
        # Get current user
        current_user = request.current_user

        # Use repository to get PVCs from database
        with get_db_session() as session:
            pvc_repo = StoragePVCRepository(session)

            # Different handling for admins vs regular users
            if current_user.is_admin:
                pvcs = pvc_repo.get_pvcs_for_admin()
            else:
                # For regular users, only show accessible PVCs
                pvcs = pvc_repo.get_pvcs_for_user(current_user.username)

            # Process the PVCs and add access information
            result = []
            for pvc in pvcs:
                # Get users with access to this PVC
                allowed_users = pvc_repo.get_pvc_users(pvc.id)

                # Convert to API model
                pvc_model = StoragePVCModel.model_validate(pvc)
                pvc_dict = pvc_model.model_dump()
                pvc_dict["allowed_users"] = allowed_users

                result.append(pvc_dict)

            return (
                jsonify({"pvcs": result}),
                HTTPStatus.OK,
            )
    except Exception as e:
        error_message = f"Failed to list PVCs: {e!s}"
        logging.error(error_message)
        return (
            jsonify({"error": error_message}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@storage_pvc_bp.route("/<int:pvc_id>", methods=["DELETE"])
@token_required
@admin_required
def delete_storage_pvc(pvc_id: int) -> tuple[dict[str, Any], int]:
    """Delete a storage PVC.

    Args:
        pvc_id: PVC ID

    Returns:
        Tuple[Dict[str, Any], int]: Response data and status code
    """
    try:
        # Use repository to get and delete PVC
        with get_db_session() as session:
            pvc_repo = StoragePVCRepository(session)

            # Get PVC from database
            pvc = pvc_repo.get_by_id(pvc_id)
            if not pvc:
                return (
                    jsonify({"error": f"PVC with ID {pvc_id} not found"}),
                    HTTPStatus.NOT_FOUND,
                )

            # Check if PVC is being used by any connection
            if pvc_repo.is_pvc_in_use(pvc.id):
                return (
                    jsonify({"error": "Cannot delete PVC that is in use by one or more connections"}),
                    HTTPStatus.CONFLICT,
                )

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

            return (
                jsonify({"message": f"PVC '{pvc.name}' deleted successfully"}),
                HTTPStatus.OK,
            )
    except Exception as e:
        error_message = f"Failed to delete PVC: {e!s}"
        logging.error(error_message)
        return (
            jsonify({"error": error_message}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@storage_pvc_bp.route("/<int:pvc_id>/access", methods=["GET"])
@token_required
@admin_required
def get_pvc_access(pvc_id: int) -> tuple[dict[str, Any], int]:
    """Get users with access to a specific PVC.

    Args:
        pvc_id: PVC ID

    Returns:
        Tuple[Dict[str, Any], int]: Response data and status code
    """
    try:
        # Get users with access
        with get_db_session() as session:
            pvc_repo = StoragePVCRepository(session)
            allowed_users = pvc_repo.get_pvc_users(pvc_id)

            return (
                jsonify({"users": allowed_users}),
                HTTPStatus.OK,
            )
    except Exception as e:
        error_message = f"Failed to get PVC access: {e!s}"
        logging.error(error_message)
        return (
            jsonify({"error": error_message}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@storage_pvc_bp.route("/<int:pvc_id>/access", methods=["POST"])
@token_required
@admin_required
def update_pvc_access(pvc_id: int) -> tuple[dict[str, Any], int]:
    """Update access to a PVC.

    Args:
        pvc_id: PVC ID

    Returns:
        Tuple[Dict[str, Any], int]: Response data and status code
    """
    try:
        # Parse input data
        data = request.get_json()
        if not data:
            return (
                jsonify({"error": "No input data provided"}),
                HTTPStatus.BAD_REQUEST,
            )

        # Get is_public and allowed_users from data
        is_public = data.get("is_public", False)
        allowed_users = data.get("allowed_users", [])

        # Use repository to update PVC access
        with get_db_session() as session:
            pvc_repo = StoragePVCRepository(session)

            # Get the PVC to check ownership
            pvc = pvc_repo.get_by_id(pvc_id)
            if not pvc:
                return (
                    jsonify({"error": f"PVC with ID {pvc_id} not found"}),
                    HTTPStatus.NOT_FOUND,
                )

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

            return (
                jsonify({"message": "PVC access updated successfully"}),
                HTTPStatus.OK,
            )
    except Exception as e:
        error_message = f"Failed to update PVC access: {e!s}"
        logging.error(error_message)
        return (
            jsonify({"error": error_message}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@storage_pvc_bp.route("/<int:pvc_id>", methods=["GET"])
@token_required
@admin_required
def get_storage_pvc_by_id(pvc_id: int) -> tuple[dict[str, Any], int]:
    """Get storage PVC details by ID.

    Args:
        pvc_id: PVC ID

    Returns:
        Tuple[Dict[str, Any], int]: Response data and status code
    """
    try:
        # Use repository to get PVC
        with get_db_session() as session:
            pvc_repo = StoragePVCRepository(session)

            # Get PVC from database
            pvc = pvc_repo.get_by_id(pvc_id)
            if not pvc:
                return (
                    jsonify({"error": f"PVC with ID {pvc_id} not found"}),
                    HTTPStatus.NOT_FOUND,
                )

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

            return (
                jsonify({"pvc": pvc_dict}),
                HTTPStatus.OK,
            )
    except Exception as e:
        error_message = f"Failed to get PVC details: {e!s}"
        logging.error(error_message)
        return (
            jsonify({"error": error_message}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@storage_pvc_bp.route("/connections/<int:pvc_id>", methods=["GET"])
@token_required
@admin_required
def get_pvc_connections(pvc_id: int) -> tuple[dict[str, Any], int]:
    """Get connections that are using a specific PVC.

    Args:
        pvc_id: PVC ID

    Returns:
        Tuple[Dict[str, Any], int]: Response data and status code
    """
    try:
        with get_db_session() as session:
            conn_repo = ConnectionRepository(session)
            connections = conn_repo.get_connections_for_pvc(pvc_id)

            connections = [
                {
                    "id": row.id,
                    "name": row.name,
                    "created_at": row.created_at.isoformat(),
                    "created_by": row.created_by,
                    "is_stopped": row.is_stopped,
                }
                for row in connections
            ]

        return (
            jsonify({"connections": connections}),
            HTTPStatus.OK,
        )
    except Exception as e:
        error_message = f"Failed to get connections for PVC: {e!s}"
        logging.error(error_message)
        return (
            jsonify({"error": error_message}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )
