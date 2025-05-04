"""Storage PVC routes module for desktop-manager-api.

This module provides API routes for managing Persistent Volume Claims (PVCs).
"""

from http import HTTPStatus
import logging
from typing import Any

from core.auth import admin_required, token_required
from database.core.session import with_db_session
from flask import Blueprint, jsonify, request
from services.connections import APIError
from services.storage_pvc import StoragePVCService


storage_pvc_bp = Blueprint("storage_pvc_bp", __name__)


@storage_pvc_bp.route("/create", methods=["POST"])
@with_db_session
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
    logging.debug("=== Received request to create a storage PVC ===")

    try:
        current_user = request.current_user
        # Parse input data
        data = request.get_json()

        # Create service instance and create storage PVC
        pvc_service = StoragePVCService()
        response_data = pvc_service.create_storage_pvc(data, current_user, request.db_session)

        return jsonify(response_data), HTTPStatus.CREATED

    except APIError as e:
        logging.error("API error in create_storage_pvc: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        error_message = f"Failed to create PVC: {e!s}"
        logging.error(error_message)
        return (
            jsonify({"error": error_message}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@storage_pvc_bp.route("/list", methods=["GET"])
@with_db_session
@token_required
def list_storage_pvcs() -> tuple[dict[str, Any], int]:
    """List storage PVCs.

    Returns:
        Tuple[Dict[str, Any], int]: Response data and status code
    """
    try:
        # Get current user
        current_user = request.current_user

        # Create service instance and list storage PVCs
        pvc_service = StoragePVCService()
        response_data = pvc_service.list_storage_pvcs(current_user, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in list_storage_pvcs: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        error_message = f"Failed to list PVCs: {e!s}"
        logging.error(error_message)
        return (
            jsonify({"error": error_message}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@storage_pvc_bp.route("/<int:pvc_id>", methods=["DELETE"])
@with_db_session
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
        # Create service instance and delete storage PVC
        pvc_service = StoragePVCService()
        response_data = pvc_service.delete_storage_pvc(pvc_id, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in delete_storage_pvc: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        error_message = f"Failed to delete PVC: {e!s}"
        logging.error(error_message)
        return (
            jsonify({"error": error_message}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@storage_pvc_bp.route("/<int:pvc_id>/access", methods=["GET"])
@with_db_session
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
        # Create service instance and get PVC access
        pvc_service = StoragePVCService()
        response_data = pvc_service.get_pvc_access(pvc_id, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in get_pvc_access: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        error_message = f"Failed to get PVC access: {e!s}"
        logging.error(error_message)
        return (
            jsonify({"error": error_message}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@storage_pvc_bp.route("/<int:pvc_id>/access", methods=["POST"])
@with_db_session
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

        # Create service instance and update PVC access
        pvc_service = StoragePVCService()
        response_data = pvc_service.update_pvc_access(pvc_id, data, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in update_pvc_access: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        error_message = f"Failed to update PVC access: {e!s}"
        logging.error(error_message)
        return (
            jsonify({"error": error_message}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@storage_pvc_bp.route("/<int:pvc_id>", methods=["GET"])
@with_db_session
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
        # Create service instance and get storage PVC by ID
        pvc_service = StoragePVCService()
        response_data = pvc_service.get_storage_pvc_by_id(pvc_id, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in get_storage_pvc_by_id: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        error_message = f"Failed to get PVC details: {e!s}"
        logging.error(error_message)
        return (
            jsonify({"error": error_message}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@storage_pvc_bp.route("/connections/<int:pvc_id>", methods=["GET"])
@with_db_session
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
        # Create service instance and get PVC connections
        pvc_service = StoragePVCService()
        response_data = pvc_service.get_pvc_connections(pvc_id, request.db_session)

        return jsonify(response_data), HTTPStatus.OK

    except APIError as e:
        logging.error("API error in get_pvc_connections: %s (status: %s)", e.message, e.status_code)
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        error_message = f"Failed to get connections for PVC: {e!s}"
        logging.error(error_message)
        return (
            jsonify({"error": error_message}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )
