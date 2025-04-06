"""Storage PVC routes module for desktop-manager-api.

This module provides API routes for managing Persistent Volume Claims (PVCs).
"""

from http import HTTPStatus
import logging
from typing import Any, Dict, Tuple

from flask import Blueprint, jsonify, request

from desktop_manager.api.models.storage_pvc import (
    StoragePVC,
)
from desktop_manager.clients.factory import client_factory
from desktop_manager.config.settings import get_settings
from desktop_manager.core.auth import token_required


storage_pvc_bp = Blueprint("storage_pvc_bp", __name__)


@storage_pvc_bp.route("/create", methods=["POST"])
@token_required
def create_storage_pvc() -> Tuple[Dict[str, Any], int]:
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
        # Get current user and check admin status
        current_user = request.current_user
        if not current_user:
            return (
                jsonify({"error": "Authentication required"}),
                HTTPStatus.UNAUTHORIZED,
            )

        # Only admins can create PVCs
        if not current_user.is_admin:
            return (
                jsonify({"error": "Admin access required to create storage PVCs"}),
                HTTPStatus.FORBIDDEN,
            )

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
        allowed_users = data.get("allowed_users", [])

        if not name:
            return (
                jsonify({"error": "Missing required field: name"}),
                HTTPStatus.BAD_REQUEST,
            )

        # Get settings and clients
        settings = get_settings()
        namespace = settings.NAMESPACE  # Always use the namespace from settings

        # Create PVC in Kubernetes
        rancher_client = client_factory.get_rancher_client()
        db_client = client_factory.get_database_client()

        # Check if PVC already exists in database
        try:
            db_client.get_storage_pvc_by_name(name)
            return (
                jsonify({"error": f"PVC with name '{name}' already exists"}),
                HTTPStatus.CONFLICT,
            )
        except Exception:
            # PVC doesn't exist, which is what we want
            logging.info("PVC '%s' does not exist yet, proceeding with creation", name)

        # Create PVC in Kubernetes
        logging.info("Creating PVC '%s' in namespace '%s' with size '%s'", name, namespace, size)
        pvc_data = rancher_client.create_pvc(
            name=name,
            namespace=namespace,
            size=size,
        )
        logging.info("PVC created successfully: %s", pvc_data)

        # Store PVC in database
        pvc_db_data = {
            "name": name,
            "namespace": namespace,
            "size": size,
            "created_by": current_user.username,
            "status": "Pending",
            "is_public": is_public,
        }

        pvc_id = db_client.create_storage_pvc(pvc_db_data)

        # Add user access if not public
        if not is_public and allowed_users:
            for username in allowed_users:
                db_client.create_storage_pvc_access(pvc_id, username)

        # Get complete PVC from database
        pvc_row = db_client.get_storage_pvc(pvc_id)
        pvc = StoragePVC.from_row(pvc_row)

        return (
            jsonify({"message": "PVC created successfully", "pvc": pvc.model_dump()}),
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
def list_storage_pvcs() -> Tuple[Dict[str, Any], int]:
    """List storage PVCs.

    Returns:
        Tuple[Dict[str, Any], int]: Response data and status code
    """
    try:
        # Get current user
        current_user = request.current_user
        if not current_user:
            return (
                jsonify({"error": "Authentication required"}),
                HTTPStatus.UNAUTHORIZED,
            )

        # Get database client
        db_client = client_factory.get_database_client()

        # Get PVCs from database - different handling for admins vs regular users
        if current_user.is_admin:
            # For admins, get all PVCs by default
            filter_by_user = request.args.get("filter_by_user", "false").lower() == "true"
            if filter_by_user:
                # Only show admin's own PVCs if filtering requested
                query = """
                SELECT * FROM storage_pvcs
                WHERE created_by = :username
                ORDER BY name ASC
                """
                pvc_rows, _ = db_client.execute_query(query, {"username": current_user.username})
            else:
                # Show all PVCs for admins
                query = """
                SELECT * FROM storage_pvcs
                ORDER BY name ASC
                """
                pvc_rows, _ = db_client.execute_query(query)
        else:
            # For regular users, only show public PVCs and ones they have access to
            query = """
            SELECT DISTINCT sp.*
            FROM storage_pvcs sp
            LEFT JOIN storage_pvc_access spa
                ON sp.id = spa.pvc_id AND spa.username = :username
            WHERE sp.is_public = TRUE
               OR sp.created_by = :username
               OR spa.username IS NOT NULL
            ORDER BY sp.name ASC
            """
            pvc_rows, _ = db_client.execute_query(query, {"username": current_user.username})

        # Process the PVCs and add access information
        result = []
        for pvc_row in pvc_rows:
            # Get users with access to this PVC
            access_query = """
            SELECT username
            FROM storage_pvc_access
            WHERE pvc_id = :pvc_id
            """
            access_rows, _ = db_client.execute_query(access_query, {"pvc_id": pvc_row["id"]})
            allowed_users = [row["username"] for row in access_rows]

            # Create PVC object
            pvc = StoragePVC.from_row(pvc_row)
            pvc_dict = pvc.model_dump()
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


@storage_pvc_bp.route("/<string:pvc_name>", methods=["GET"])
@token_required
def get_storage_pvc(pvc_name: str) -> Tuple[Dict[str, Any], int]:
    """Get storage PVC details.

    Args:
        pvc_name: PVC name

    Returns:
        Tuple[Dict[str, Any], int]: Response data and status code
    """
    try:
        # Get current user
        current_user = request.current_user
        if not current_user:
            return (
                jsonify({"error": "Authentication required"}),
                HTTPStatus.UNAUTHORIZED,
            )

        # Get database client
        db_client = client_factory.get_database_client()

        # Get PVC from database
        pvc_row = db_client.get_storage_pvc_by_name(pvc_name)

        # Check permission
        has_access = (
            current_user.is_admin
            or pvc_row["created_by"] == current_user.username
            or pvc_row.get("is_public", False)
        )

        if not has_access:
            # Check if user has explicit access
            access_query = """
            SELECT 1 FROM storage_pvc_access
            WHERE pvc_id = :pvc_id AND username = :username
            """
            access_rows, access_count = db_client.execute_query(
                access_query, {"pvc_id": pvc_row["id"], "username": current_user.username}
            )

            if access_count == 0:
                return (
                    jsonify({"error": "You do not have permission to view this PVC"}),
                    HTTPStatus.FORBIDDEN,
                )

        # Get PVC details from Rancher
        rancher_client = client_factory.get_rancher_client()
        try:
            pvc_k8s_data = rancher_client.get_pvc(
                name=pvc_name,
                namespace=pvc_row["namespace"],
            )
            # Update status if needed
            k8s_status = pvc_k8s_data.get("status", {}).get("phase", "Unknown")
            if k8s_status != pvc_row["status"]:
                db_client.update_storage_pvc(
                    pvc_row["id"],
                    {"status": k8s_status},
                )
                pvc_row["status"] = k8s_status
        except Exception as e:
            logging.warning("Failed to get PVC details from Rancher: %s", str(e))
            # Continue with database data

        # Get access information
        access_query = """
        SELECT username FROM storage_pvc_access
        WHERE pvc_id = :pvc_id
        """
        access_rows, _ = db_client.execute_query(access_query, {"pvc_id": pvc_row["id"]})
        allowed_users = [row["username"] for row in access_rows]

        # Create PVC with access information
        pvc = StoragePVC.from_row(pvc_row)
        pvc_dict = pvc.model_dump()
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


@storage_pvc_bp.route("/<string:pvc_name>", methods=["DELETE"])
@token_required
def delete_storage_pvc(pvc_name: str) -> Tuple[Dict[str, Any], int]:
    """Delete a storage PVC.

    Args:
        pvc_name: PVC name

    Returns:
        Tuple[Dict[str, Any], int]: Response data and status code
    """
    try:
        # Get current user and check admin status
        current_user = request.current_user
        if not current_user:
            return (
                jsonify({"error": "Authentication required"}),
                HTTPStatus.UNAUTHORIZED,
            )

        # Only admins can delete PVCs
        if not current_user.is_admin:
            return (
                jsonify({"error": "Admin access required to delete storage PVCs"}),
                HTTPStatus.FORBIDDEN,
            )

        # Get database client
        db_client = client_factory.get_database_client()

        # Get PVC from database
        pvc_row = db_client.get_storage_pvc_by_name(pvc_name)

        # Check if PVC is being used by any connection
        connection_pvcs = db_client.get_connection_pvcs(pvc_row["id"])
        if connection_pvcs:
            return (
                jsonify({"error": "Cannot delete PVC that is in use by one or more connections"}),
                HTTPStatus.CONFLICT,
            )

        # Delete PVC from Kubernetes
        rancher_client = client_factory.get_rancher_client()
        try:
            rancher_client.delete_pvc(
                name=pvc_name,
                namespace=pvc_row["namespace"],
            )
        except Exception as e:
            logging.warning("Failed to delete PVC from Kubernetes: %s", str(e))
            # Continue with database deletion

        # Delete PVC from database
        db_client.delete_storage_pvc(pvc_row["id"])

        return (
            jsonify({"message": f"PVC '{pvc_name}' deleted successfully"}),
            HTTPStatus.OK,
        )
    except Exception as e:
        error_message = f"Failed to delete PVC: {e!s}"
        logging.error(error_message)
        return (
            jsonify({"error": error_message}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@storage_pvc_bp.route("/connection/<int:connection_id>", methods=["GET"])
@token_required
def get_connection_pvcs(connection_id: int) -> Tuple[Dict[str, Any], int]:
    """Get PVCs associated with a connection.

    Args:
        connection_id: Connection ID

    Returns:
        Tuple[Dict[str, Any], int]: Response data and status code
    """
    try:
        # Get current user
        current_user = request.current_user
        if not current_user:
            return (
                jsonify({"error": "Authentication required"}),
                HTTPStatus.UNAUTHORIZED,
            )

        # Get database client
        db_client = client_factory.get_database_client()

        # Check if connection exists and user has permission
        connection_query = """
        SELECT * FROM connections WHERE id = :connection_id
        """
        connection_rows, connection_count = db_client.execute_query(
            connection_query,
            {"connection_id": connection_id},
        )

        if connection_count == 0:
            return (
                jsonify({"error": f"Connection with ID {connection_id} not found"}),
                HTTPStatus.NOT_FOUND,
            )

        connection = connection_rows[0]
        if not current_user.is_admin and connection["created_by"] != current_user.username:
            return (
                jsonify({"error": "You do not have permission to view this connection's PVCs"}),
                HTTPStatus.FORBIDDEN,
            )

        # Get PVCs associated with the connection
        pvc_rows = db_client.get_connection_pvcs(connection_id)

        # Include connection_name in the response for display
        connection_name = connection["name"]

        pvcs = [
            {
                "id": row["id"],
                "name": row["name"],
                "namespace": row["namespace"],
                "size": row["size"],
                "is_public": row["is_public"],
                "created_at": row["created_at"].isoformat(),
                "created_by": row["created_by"],
                "status": row["status"],
                "last_updated": row["last_updated"].isoformat(),
                "mapping_id": row["mapping_id"],
                "connection_name": connection_name,
            }
            for row in pvc_rows
        ]

        return (
            jsonify({"pvcs": pvcs}),
            HTTPStatus.OK,
        )
    except Exception as e:
        error_message = f"Failed to get connection PVCs: {e!s}"
        logging.error(error_message)
        return (
            jsonify({"error": error_message}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@storage_pvc_bp.route("/connection/<int:connection_id>/attach", methods=["POST"])
@token_required
def attach_pvc_to_connection(connection_id: int) -> Tuple[Dict[str, Any], int]:
    """Attach a PVC to a connection.

    Args:
        connection_id: Connection ID

    Returns:
        Tuple[Dict[str, Any], int]: Response data and status code
    """
    try:
        # Get current user
        current_user = request.current_user
        if not current_user:
            return (
                jsonify({"error": "Authentication required"}),
                HTTPStatus.UNAUTHORIZED,
            )

        # Parse and validate input data
        data = request.get_json()
        if not data or "pvc_id" not in data:
            return (
                jsonify({"error": "Missing required field: pvc_id"}),
                HTTPStatus.BAD_REQUEST,
            )

        pvc_id = data["pvc_id"]

        # Get database client
        db_client = client_factory.get_database_client()

        # Check if connection exists and user has permission
        connection_query = """
        SELECT * FROM connections WHERE id = :connection_id
        """
        connection_rows, connection_count = db_client.execute_query(
            connection_query,
            {"connection_id": connection_id},
        )

        if connection_count == 0:
            return (
                jsonify({"error": f"Connection with ID {connection_id} not found"}),
                HTTPStatus.NOT_FOUND,
            )

        connection = connection_rows[0]
        if not current_user.is_admin and connection["created_by"] != current_user.username:
            return (
                jsonify({"error": "You do not have permission to modify this connection"}),
                HTTPStatus.FORBIDDEN,
            )

        # Check if PVC exists and user has permission
        try:
            pvc_row = db_client.get_storage_pvc(pvc_id)
            if not current_user.is_admin and pvc_row["created_by"] != current_user.username:
                return (
                    jsonify({"error": "You do not have permission to use this PVC"}),
                    HTTPStatus.FORBIDDEN,
                )
        except Exception as e:
            return (
                jsonify({"error": f"PVC with ID {pvc_id} not found: {e!s}"}),
                HTTPStatus.NOT_FOUND,
            )

        # Check if connection already has this PVC
        existing_pvcs = db_client.get_connection_pvcs(connection_id)
        for existing_pvc in existing_pvcs:
            if existing_pvc["id"] == pvc_id:
                return (
                    jsonify({"error": "PVC is already attached to this connection"}),
                    HTTPStatus.CONFLICT,
                )

        # Map connection to PVC
        mapping_id = db_client.map_connection_to_pvc(connection_id, pvc_id)

        return (
            jsonify(
                {
                    "message": "PVC attached successfully",
                    "mapping_id": mapping_id,
                }
            ),
            HTTPStatus.OK,
        )
    except Exception as e:
        error_message = f"Failed to attach PVC to connection: {e!s}"
        logging.error(error_message)
        return (
            jsonify({"error": error_message}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@storage_pvc_bp.route("/connection/detach/<int:mapping_id>", methods=["POST"])
@token_required
def detach_pvc_from_connection(mapping_id: int) -> Tuple[Dict[str, Any], int]:
    """Detach a PVC from a connection.

    Args:
        mapping_id: Connection-PVC mapping ID

    Returns:
        Tuple[Dict[str, Any], int]: Response data and status code
    """
    try:
        # Get current user
        current_user = request.current_user
        if not current_user:
            return (
                jsonify({"error": "Authentication required"}),
                HTTPStatus.UNAUTHORIZED,
            )

        # Get database client
        db_client = client_factory.get_database_client()

        # Check if mapping exists and user has permission
        mapping_query = """
        SELECT cp.*, c.created_by as connection_owner, p.created_by as pvc_owner
        FROM connection_pvcs cp
        JOIN connections c ON cp.connection_id = c.id
        JOIN storage_pvcs p ON cp.pvc_id = p.id
        WHERE cp.id = :mapping_id
        """
        mapping_rows, mapping_count = db_client.execute_query(
            mapping_query,
            {"mapping_id": mapping_id},
        )

        if mapping_count == 0:
            return (
                jsonify({"error": f"Mapping with ID {mapping_id} not found"}),
                HTTPStatus.NOT_FOUND,
            )

        mapping = mapping_rows[0]
        if (
            not current_user.is_admin
            and mapping["connection_owner"] != current_user.username
            and mapping["pvc_owner"] != current_user.username
        ):
            return (
                jsonify({"error": "You do not have permission to detach this PVC"}),
                HTTPStatus.FORBIDDEN,
            )

        # Unmap connection from PVC
        db_client.unmap_connection_pvc(mapping_id)

        return (
            jsonify({"message": "PVC detached successfully"}),
            HTTPStatus.OK,
        )
    except Exception as e:
        error_message = f"Failed to detach PVC from connection: {e!s}"
        logging.error(error_message)
        return (
            jsonify({"error": error_message}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@storage_pvc_bp.route("/<int:pvc_id>/access", methods=["GET"])
@token_required
def get_pvc_access(pvc_id: int) -> Tuple[Dict[str, Any], int]:
    """Get users with access to a specific PVC.

    Args:
        pvc_id: PVC ID

    Returns:
        Tuple[Dict[str, Any], int]: Response data and status code
    """
    try:
        # Get current user
        current_user = request.current_user
        if not current_user:
            return (
                jsonify({"error": "Authentication required"}),
                HTTPStatus.UNAUTHORIZED,
            )

        # Get database client
        db_client = client_factory.get_database_client()

        # Get the PVC to check ownership
        try:
            pvc_row = db_client.get_storage_pvc(pvc_id)
        except Exception:
            return (
                jsonify({"error": f"PVC with ID {pvc_id} not found"}),
                HTTPStatus.NOT_FOUND,
            )

        # Check permission
        if not current_user.is_admin and pvc_row["created_by"] != current_user.username:
            return (
                jsonify({"error": "You do not have permission to view access for this PVC"}),
                HTTPStatus.FORBIDDEN,
            )

        # Get users with access
        access_query = """
        SELECT u.id, u.username, u.email
        FROM users u
        JOIN storage_pvc_access spa ON u.username = spa.username
        WHERE spa.pvc_id = :pvc_id
        ORDER BY u.username
        """
        users, _ = db_client.execute_query(access_query, {"pvc_id": pvc_id})

        return (
            jsonify({"users": users}),
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
def update_pvc_access(pvc_id: int) -> Tuple[Dict[str, Any], int]:
    """Update access to a PVC.

    Args:
        pvc_id: PVC ID

    Returns:
        Tuple[Dict[str, Any], int]: Response data and status code
    """
    try:
        # Get current user
        current_user = request.current_user
        if not current_user:
            return (
                jsonify({"error": "Authentication required"}),
                HTTPStatus.UNAUTHORIZED,
            )

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

        # Get database client
        db_client = client_factory.get_database_client()

        # Get the PVC to check ownership
        try:
            pvc_row = db_client.get_storage_pvc(pvc_id)
        except Exception:
            return (
                jsonify({"error": f"PVC with ID {pvc_id} not found"}),
                HTTPStatus.NOT_FOUND,
            )

        # Check permission
        if not current_user.is_admin and pvc_row["created_by"] != current_user.username:
            return (
                jsonify({"error": "You do not have permission to modify access for this PVC"}),
                HTTPStatus.FORBIDDEN,
            )

        # Update is_public status
        db_client.update_storage_pvc(pvc_id, {"is_public": is_public})

        # Clear existing access
        clear_access_query = """
        DELETE FROM storage_pvc_access
        WHERE pvc_id = :pvc_id
        """
        db_client.execute_query(clear_access_query, {"pvc_id": pvc_id})

        # Add new access if not public
        if not is_public and allowed_users:
            for username in allowed_users:
                try:
                    db_client.create_storage_pvc_access(pvc_id, username)
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
def get_storage_pvc_by_id(pvc_id: int) -> Tuple[Dict[str, Any], int]:
    """Get storage PVC details by ID.

    Args:
        pvc_id: PVC ID

    Returns:
        Tuple[Dict[str, Any], int]: Response data and status code
    """
    try:
        # Get current user
        current_user = request.current_user
        if not current_user:
            return (
                jsonify({"error": "Authentication required"}),
                HTTPStatus.UNAUTHORIZED,
            )

        # Get database client
        db_client = client_factory.get_database_client()

        # Get PVC from database
        try:
            pvc_row = db_client.get_storage_pvc(pvc_id)
        except Exception:
            return (
                jsonify({"error": f"PVC with ID {pvc_id} not found"}),
                HTTPStatus.NOT_FOUND,
            )

        # Check permission
        has_access = (
            current_user.is_admin
            or pvc_row["created_by"] == current_user.username
            or pvc_row.get("is_public", False)
        )

        if not has_access:
            # Check if user has explicit access
            access_query = """
            SELECT 1 FROM storage_pvc_access
            WHERE pvc_id = :pvc_id AND username = :username
            """
            access_rows, access_count = db_client.execute_query(
                access_query, {"pvc_id": pvc_row["id"], "username": current_user.username}
            )

            if access_count == 0:
                return (
                    jsonify({"error": "You do not have permission to view this PVC"}),
                    HTTPStatus.FORBIDDEN,
                )

        # Get PVC details from Rancher
        rancher_client = client_factory.get_rancher_client()
        try:
            pvc_k8s_data = rancher_client.get_pvc(
                name=pvc_row["name"],
                namespace=pvc_row["namespace"],
            )
            # Update status if needed
            k8s_status = pvc_k8s_data.get("status", {}).get("phase", "Unknown")
            if k8s_status != pvc_row["status"]:
                db_client.update_storage_pvc(
                    pvc_row["id"],
                    {"status": k8s_status},
                )
                pvc_row["status"] = k8s_status
        except Exception as e:
            logging.warning("Failed to get PVC details from Rancher: %s", str(e))
            # Continue with database data

        # Get access information
        access_query = """
        SELECT username FROM storage_pvc_access
        WHERE pvc_id = :pvc_id
        """
        access_rows, _ = db_client.execute_query(access_query, {"pvc_id": pvc_row["id"]})
        allowed_users = [row["username"] for row in access_rows]

        # Create PVC with access information
        pvc = StoragePVC.from_row(pvc_row)
        pvc_dict = pvc.model_dump()
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
def get_pvc_connections(pvc_id: int) -> Tuple[Dict[str, Any], int]:
    """Get connections that are using a specific PVC.

    Args:
        pvc_id: PVC ID

    Returns:
        Tuple[Dict[str, Any], int]: Response data and status code
    """
    try:
        # Get current user
        current_user = request.current_user
        if not current_user:
            return (
                jsonify({"error": "Authentication required"}),
                HTTPStatus.UNAUTHORIZED,
            )

        # Get database client
        db_client = client_factory.get_database_client()

        # Check if PVC exists and user has permission
        try:
            pvc_row = db_client.get_storage_pvc(pvc_id)
        except Exception:
            return (
                jsonify({"error": f"PVC with ID {pvc_id} not found"}),
                HTTPStatus.NOT_FOUND,
            )

        # Check permission - if admin or creator, or if PVC is public
        has_access = (
            current_user.is_admin
            or pvc_row["created_by"] == current_user.username
            or pvc_row.get("is_public", False)
        )

        if not has_access:
            # Check if user has explicit access
            access_query = """
            SELECT 1 FROM storage_pvc_access
            WHERE pvc_id = :pvc_id AND username = :username
            """
            access_rows, access_count = db_client.execute_query(
                access_query, {"pvc_id": pvc_id, "username": current_user.username}
            )

            if access_count == 0:
                return (
                    jsonify(
                        {"error": "You do not have permission to view connections for this PVC"}
                    ),
                    HTTPStatus.FORBIDDEN,
                )

        # Get connections using this PVC
        connections_query = """
        SELECT c.id, c.name, c.created_at, c.created_by, c.is_stopped,
               cp.id AS mapping_id
        FROM connections c
        JOIN connection_pvcs cp ON c.id = cp.connection_id
        WHERE cp.pvc_id = :pvc_id
        """

        connection_rows, _ = db_client.execute_query(connections_query, {"pvc_id": pvc_id})

        # Format connections for response
        connections = [
            {
                "id": row["id"],
                "name": row["name"],
                "created_at": row["created_at"].isoformat(),
                "created_by": row["created_by"],
                "is_stopped": row["is_stopped"],
                "mapping_id": row["mapping_id"],
            }
            for row in connection_rows
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
