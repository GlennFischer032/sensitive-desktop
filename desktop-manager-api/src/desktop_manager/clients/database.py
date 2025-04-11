"""Database client module for desktop-manager-api.

This module provides a client for database operations.
"""

import logging
from typing import Any, Union

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.sql.elements import TextClause

from desktop_manager.clients.base import APIError, BaseClient
from desktop_manager.config.settings import get_settings


class DatabaseClient(BaseClient):
    """Client for database operations.

    This client provides methods for:
    - Executing SQL queries
    - Managing database connections
    - Handling database transactions
    """

    def __init__(self, connection_string: str | None = None):
        """Initialize DatabaseClient.

        Args:
            connection_string: Database connection string
        """
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        settings = get_settings()
        self.connection_string = connection_string or settings.database_url
        self._engine: Engine | None = None

    @property
    def engine(self) -> Engine:
        """Get SQLAlchemy engine.

        Returns:
            Engine: SQLAlchemy engine
        """
        if self._engine is None:
            self.logger.info("Creating database engine with connection string: %s", self.connection_string)
            self._engine = create_engine(self.connection_string)
        return self._engine

    def execute_query(
        self, query: Union[str, "TextClause"], params: dict[str, Any] | None = None
    ) -> tuple[list[dict[str, Any]], int]:
        """Execute a SQL query.

        Args:
            query: SQL query string or TextClause object
            params: Query parameters

        Returns:
            Tuple[List[Dict[str, Any]], int]: Query results and row count

        Raises:
            APIError: If query execution fails
        """
        try:
            self.logger.info("Executing query: %s with params: %s", query, params)
            with self.engine.connect() as connection:
                # For non-SELECT queries, use a transaction context to ensure commit
                is_select = False
                if isinstance(query, str):
                    is_select = query.lstrip().upper().startswith("SELECT")
                    query_obj = text(query)
                else:
                    # If it's already a TextClause, use it directly
                    # We'll assume it's not a SELECT if it's already a TextClause
                    query_obj = query

                if not is_select:
                    conn_with_autocommit = connection.execution_options(isolation_level="AUTOCOMMIT")
                    result = conn_with_autocommit.execute(query_obj, params or {})
                else:
                    result = connection.execute(query_obj, params or {})

                if result.returns_rows:
                    # Convert result to list of dictionaries
                    rows = [dict(row._mapping) for row in result]
                    row_count = len(rows)
                    self.logger.info("Query returned %d rows", row_count)
                    return rows, row_count
                else:
                    row_count = result.rowcount
                    self.logger.info("Query affected %d rows", row_count)
                    return [], row_count
        except SQLAlchemyError as e:
            error_message = f"Database query execution failed: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e
        except Exception as e:
            error_message = f"Unexpected error executing database query: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def execute_transaction(self, queries: list[tuple[str, dict[str, Any] | None]]) -> list[list[dict[str, Any]] | int]:
        """Execute multiple queries in a transaction.

        Args:
            queries: List of (query, params) tuples

        Returns:
            List[Union[List[Dict[str, Any]], int]]: List of results

        Raises:
            APIError: If transaction execution fails
        """
        try:
            self.logger.info("Executing transaction with %d queries", len(queries))
            results = []
            with self.engine.begin() as connection:
                for query, params in queries:
                    self.logger.info("Executing query in transaction: %s with params: %s", query, params)
                    result = connection.execute(text(query), params or {})
                    if result.returns_rows:
                        # Convert result to list of dictionaries
                        rows = [dict(row._mapping) for row in result]
                        results.append(rows)
                        self.logger.info("Query returned %d rows", len(rows))
                    else:
                        results.append(result.rowcount)
                        self.logger.info("Query affected %d rows", result.rowcount)
            return results
        except SQLAlchemyError as e:
            error_message = f"Database transaction execution failed: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e
        except Exception as e:
            error_message = f"Unexpected error executing database transaction: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def get_connection_details(self, connection_name: str) -> dict[str, Any]:
        """Get connection details from the database.

        Args:
            connection_name: Connection name

        Returns:
            Dict[str, Any]: Connection details

        Raises:
            APIError: If connection details retrieval fails
        """
        try:
            query = """
            SELECT c.id, c.name, c.connection_type, c.ip_address, c.port, c.username, c.password,
                   c.domain, c.security, c.ignore_cert, c.disable_audio, c.enable_printing,
                   c.enable_drive, c.create_drive_path, c.sftp_enable, c.sftp_port,
                   c.sftp_username, c.sftp_password, c.sftp_root_path, c.sftp_server_alive_interval,
                   c.color_scheme, c.clipboard_encoding, c.wol_mac_address, c.wol_broadcast_address,
                   c.wol_udp_port, c.rdp_gateway_hostname, c.rdp_gateway_port, c.rdp_gateway_username,
                   c.rdp_gateway_password, c.rdp_gateway_domain, c.rdp_initial_program,
                   c.rdp_client_name, c.rdp_keyboard_layout, c.rdp_width, c.rdp_height,
                   c.rdp_dpi, c.rdp_color_depth, c.rdp_console, c.rdp_server_layout,
                   c.rdp_timezone, c.vnc_repeater_dest_host, c.vnc_repeater_dest_port,
                   c.vnc_password_encoding, c.ssh_passphrase, c.ssh_private_key,
                   c.ssh_host_key, c.ssh_server_alive_interval, c.ssh_server_alive_count_max,
                   c.ssh_color_scheme, c.ssh_font_name, c.ssh_font_size, c.ssh_enable_agent,
                   c.ssh_agent_socket, c.ssh_force_command, c.telnet_username_regex,
                   c.telnet_password_regex, c.telnet_login_success_regex, c.telnet_login_failure_regex,
                   c.kubernetes_use_ssl, c.kubernetes_client_cert, c.kubernetes_client_key,
                   c.kubernetes_ca_cert, c.kubernetes_namespace, c.kubernetes_pod,
                   c.kubernetes_container, c.kubernetes_use_proxy, c.kubernetes_proxy_type,
                   c.kubernetes_proxy_hostname, c.kubernetes_proxy_port, c.kubernetes_proxy_username,
                   c.kubernetes_proxy_password, c.kubernetes_proxy_encryption_method
            FROM connections c
            WHERE c.name = :connection_name
            """
            rows, count = self.execute_query(query, {"connection_name": connection_name})
            if count == 0:
                error_message = f"Connection '{connection_name}' not found"
                self.logger.error(error_message)
                raise APIError(error_message, status_code=404)

            # Return the first row as connection details
            self.logger.info("Retrieved connection details for '%s'", connection_name)
            return rows[0]
        except APIError:
            # Re-raise APIError
            raise
        except Exception as e:
            error_message = f"Failed to get connection details: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def list_connections(self) -> list[dict[str, Any]]:
        """List all connections from the database.

        Returns:
            List[Dict[str, Any]]: List of connections

        Raises:
            APIError: If connections retrieval fails
        """
        try:
            query = """
            SELECT c.id, c.name, c.connection_type, c.ip_address
            FROM connections c
            ORDER BY c.name
            """
            rows, _ = self.execute_query(query)
            self.logger.info("Retrieved %d connections", len(rows))
            return rows
        except Exception as e:
            error_message = f"Failed to list connections: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def add_connection(self, connection_data: dict[str, Any]) -> int:
        """Add a new connection to the database.

        Args:
            connection_data: Connection data

        Returns:
            int: Connection ID

        Raises:
            APIError: If connection creation fails
        """
        try:
            fields = []
            values = {}
            placeholders = []

            for key, value in connection_data.items():
                if value is not None:
                    fields.append(key)
                    placeholders.append(f":{key}")
                    values[key] = value

            # Use a safe approach with text() and named parameters
            # We're using named parameters which are safe against SQL injection
            # ruff: noqa: S608
            query = text(
                """
            INSERT INTO connections ({})
            VALUES ({})
            RETURNING id
            """.format(", ".join(fields), ", ".join(placeholders))
            )

            rows, _ = self.execute_query(query, values)
            connection_id = rows[0]["id"]
            self.logger.info("Added new connection with ID %d", connection_id)
            return connection_id
        except Exception as e:
            error_message = f"Failed to add connection: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def update_connection(self, connection_id: int, connection_data: dict[str, Any]) -> None:
        """Update a connection in the database.

        Args:
            connection_id: Connection ID
            connection_data: Connection data

        Raises:
            APIError: If connection update fails
        """
        try:
            # Build the query dynamically based on the provided fields
            set_clauses = []
            values = {"id": connection_id}

            for key, value in connection_data.items():
                set_clauses.append(f"{key} = :{key}")
                values[key] = value

            # Use a safe approach with text() and named parameters
            # We're using named parameters which are safe against SQL injection
            # ruff: noqa: S608
            query = text(
                """
            UPDATE connections
            SET {}
            WHERE id = :id
            """.format(", ".join(set_clauses))
            )

            _, affected_rows = self.execute_query(query, values)
            if affected_rows == 0:
                error_message = f"Connection with ID {connection_id} not found"
                self.logger.error(error_message)
                raise APIError(error_message, status_code=404)

            self.logger.info("Updated connection with ID %d", connection_id)
        except APIError:
            # Re-raise APIError
            raise
        except Exception as e:
            error_message = f"Failed to update connection: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def delete_connection(self, connection_name: str) -> None:
        """Delete a connection from the database.

        Args:
            connection_name: Connection name

        Raises:
            APIError: If connection deletion fails
        """
        try:
            query = """
            DELETE FROM connections
            WHERE name = :connection_name
            """

            _, affected_rows = self.execute_query(query, {"connection_name": connection_name})
            if affected_rows == 0:
                error_message = f"Connection '{connection_name}' not found"
                self.logger.error(error_message)
                raise APIError(error_message, status_code=404)

            self.logger.info("Deleted connection '%s'", connection_name)
        except APIError:
            # Re-raise APIError
            raise
        except Exception as e:
            error_message = f"Failed to delete connection: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def create_storage_pvc(self, pvc_data: dict[str, Any]) -> int:
        """Create a new storage PVC record in the database.

        Args:
            pvc_data: PVC data including name, namespace, size, created_by, is_public

        Returns:
            int: PVC ID

        Raises:
            APIError: If PVC creation fails
        """
        try:
            fields = []
            values = {}
            placeholders = []

            for key, value in pvc_data.items():
                if value is not None:
                    fields.append(key)
                    placeholders.append(f":{key}")
                    values[key] = value

            query = text(
                """
            INSERT INTO storage_pvcs ({})
            VALUES ({})
            RETURNING id
            """.format(", ".join(fields), ", ".join(placeholders))
            )

            rows, _ = self.execute_query(query, values)
            pvc_id = rows[0]["id"]
            self.logger.info("Added new storage PVC with ID %d", pvc_id)
            return pvc_id
        except Exception as e:
            error_message = f"Failed to create storage PVC: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def get_storage_pvc(self, pvc_id: int) -> dict[str, Any]:
        """Get storage PVC details from the database.

        Args:
            pvc_id: PVC ID

        Returns:
            Dict[str, Any]: PVC details

        Raises:
            APIError: If PVC retrieval fails
        """
        try:
            query = """
            SELECT id, name, namespace, size, created_at, created_by,
                  status, last_updated, is_public
            FROM storage_pvcs
            WHERE id = :pvc_id
            """
            rows, count = self.execute_query(query, {"pvc_id": pvc_id})
            if count == 0:
                error_message = f"Storage PVC with ID {pvc_id} not found"
                self.logger.error(error_message)
                raise APIError(error_message, status_code=404)

            self.logger.info("Retrieved storage PVC with ID %d", pvc_id)
            return rows[0]
        except APIError:
            # Re-raise APIError
            raise
        except Exception as e:
            error_message = f"Failed to get storage PVC: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def get_storage_pvc_by_name(self, name: str) -> dict[str, Any]:
        """Get storage PVC details by name from the database.

        Args:
            name: PVC name

        Returns:
            Dict[str, Any]: PVC details

        Raises:
            APIError: If PVC retrieval fails
        """
        try:
            query = """
            SELECT id, name, namespace, size, created_at, created_by,
                  status, last_updated, is_public
            FROM storage_pvcs
            WHERE name = :name
            """
            rows, count = self.execute_query(query, {"name": name})
            if count == 0:
                error_message = f"Storage PVC with name '{name}' not found"
                self.logger.error(error_message)
                raise APIError(error_message, status_code=404)

            self.logger.info("Retrieved storage PVC with name '%s'", name)
            return rows[0]
        except APIError:
            # Re-raise APIError
            raise
        except Exception as e:
            error_message = f"Failed to get storage PVC by name: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def list_storage_pvcs(self, created_by: str | None = None) -> list[dict[str, Any]]:
        """List storage PVCs from the database.

        Args:
            created_by: Filter by creator username (optional)

        Returns:
            List[Dict[str, Any]]: List of PVCs

        Raises:
            APIError: If PVC listing fails
        """
        try:
            query = """
            SELECT id, name, namespace, size, created_at, created_by,
                  status, last_updated, is_public
            FROM storage_pvcs
            """
            params = {}

            if created_by:
                query += " WHERE created_by = :created_by"
                params["created_by"] = created_by

            query += " ORDER BY created_at DESC"

            rows, _ = self.execute_query(query, params)
            self.logger.info("Retrieved %d storage PVCs", len(rows))
            return rows
        except Exception as e:
            error_message = f"Failed to list storage PVCs: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def update_storage_pvc(self, pvc_id: int, pvc_data: dict[str, Any]) -> None:
        """Update a storage PVC in the database.

        Args:
            pvc_id: PVC ID
            pvc_data: PVC data to update

        Raises:
            APIError: If PVC update fails
        """
        try:
            # Build the query dynamically based on the provided fields
            set_clauses = []
            values = {"id": pvc_id}

            for key, value in pvc_data.items():
                set_clauses.append(f"{key} = :{key}")
                values[key] = value

            query = text(
                """
            UPDATE storage_pvcs
            SET {}
            WHERE id = :id
            """.format(", ".join(set_clauses))
            )

            _, affected_rows = self.execute_query(query, values)
            if affected_rows == 0:
                error_message = f"Storage PVC with ID {pvc_id} not found"
                self.logger.error(error_message)
                raise APIError(error_message, status_code=404)

            self.logger.info("Updated storage PVC with ID %d", pvc_id)
        except APIError:
            # Re-raise APIError
            raise
        except Exception as e:
            error_message = f"Failed to update storage PVC: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def delete_storage_pvc(self, pvc_id: int) -> None:
        """Delete a storage PVC from the database.

        Args:
            pvc_id: PVC ID

        Raises:
            APIError: If PVC deletion fails
        """
        try:
            query = """
            DELETE FROM storage_pvcs
            WHERE id = :pvc_id
            """

            _, affected_rows = self.execute_query(query, {"pvc_id": pvc_id})
            if affected_rows == 0:
                error_message = f"Storage PVC with ID {pvc_id} not found"
                self.logger.error(error_message)
                raise APIError(error_message, status_code=404)

            self.logger.info("Deleted storage PVC with ID %d", pvc_id)
        except APIError:
            # Re-raise APIError
            raise
        except Exception as e:
            error_message = f"Failed to delete storage PVC: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def map_connection_to_pvc(self, connection_id: int, pvc_id: int) -> int:
        """Map a connection to a storage PVC.

        Args:
            connection_id: Connection ID
            pvc_id: PVC ID

        Returns:
            int: Mapping ID

        Raises:
            APIError: If mapping creation fails
        """
        try:
            query = """
            INSERT INTO connection_pvcs (connection_id, pvc_id)
            VALUES (:connection_id, :pvc_id)
            RETURNING id
            """

            rows, _ = self.execute_query(query, {"connection_id": connection_id, "pvc_id": pvc_id})
            mapping_id = rows[0]["id"]
            self.logger.info(
                "Mapped connection ID %d to PVC ID %d with mapping ID %d",
                connection_id,
                pvc_id,
                mapping_id,
            )
            return mapping_id
        except Exception as e:
            error_message = f"Failed to map connection to PVC: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def get_connection_pvcs(self, connection_id: int) -> list[dict[str, Any]]:
        """Get PVCs mapped to a connection.

        Args:
            connection_id: Connection ID

        Returns:
            List[Dict[str, Any]]: List of PVCs

        Raises:
            APIError: If PVC retrieval fails
        """
        try:
            query = """
            SELECT p.id, p.name, p.namespace, p.size, p.created_at, p.created_by,
                  p.status, p.last_updated, p.is_public, cp.id AS mapping_id
            FROM storage_pvcs p
            JOIN connection_pvcs cp ON p.id = cp.pvc_id
            WHERE cp.connection_id = :connection_id
            """

            rows, _ = self.execute_query(query, {"connection_id": connection_id})
            self.logger.info("Retrieved %d PVCs for connection ID %d", len(rows), connection_id)
            return rows
        except Exception as e:
            error_message = f"Failed to get connection PVCs: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def unmap_connection_pvc(self, mapping_id: int) -> None:
        """Remove a connection to PVC mapping.

        Args:
            mapping_id: Mapping ID

        Raises:
            APIError: If mapping deletion fails
        """
        try:
            query = """
            DELETE FROM connection_pvcs
            WHERE id = :mapping_id
            """

            _, affected_rows = self.execute_query(query, {"mapping_id": mapping_id})
            if affected_rows == 0:
                error_message = f"Connection PVC mapping with ID {mapping_id} not found"
                self.logger.error(error_message)
                raise APIError(error_message, status_code=404)

            self.logger.info("Deleted connection PVC mapping with ID %d", mapping_id)
        except APIError:
            # Re-raise APIError
            raise
        except Exception as e:
            error_message = f"Failed to unmap connection PVC: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def create_storage_pvc_access(self, pvc_id: int, username: str) -> int:
        """Create a storage PVC access record in the database.

        Args:
            pvc_id: PVC ID
            username: Username to grant access

        Returns:
            int: Access record ID

        Raises:
            APIError: If access record creation fails
        """
        try:
            query = """
            INSERT INTO storage_pvc_access (pvc_id, username)
            VALUES (:pvc_id, :username)
            RETURNING id
            """
            rows, _ = self.execute_query(query, {"pvc_id": pvc_id, "username": username})
            access_id = rows[0]["id"]
            self.logger.info("Added storage PVC access for PVC ID %d and user %s", pvc_id, username)
            return access_id
        except Exception as e:
            error_message = f"Failed to create storage PVC access: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e
