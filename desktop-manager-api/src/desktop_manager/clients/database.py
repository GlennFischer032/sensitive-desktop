"""Database client module for desktop-manager-api.

This module provides a client for database operations.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple, Union

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from desktop_manager.clients.base import APIError, BaseClient
from desktop_manager.config.settings import get_settings


class DatabaseClient(BaseClient):
    """Client for database operations.

    This client provides methods for:
    - Executing SQL queries
    - Managing database connections
    - Handling database transactions
    """

    def __init__(self, connection_string: Optional[str] = None):
        """Initialize DatabaseClient.

        Args:
            connection_string: Database connection string
        """
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        settings = get_settings()
        self.connection_string = connection_string or settings.DATABASE_URL
        self._engine: Optional[Engine] = None

    @property
    def engine(self) -> Engine:
        """Get SQLAlchemy engine.

        Returns:
            Engine: SQLAlchemy engine
        """
        if self._engine is None:
            self.logger.info(
                "Creating database engine with connection string: %s", self.connection_string
            )
            self._engine = create_engine(self.connection_string)
        return self._engine

    def execute_query(
        self, query: str, params: Optional[Dict[str, Any]] = None
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Execute a SQL query.

        Args:
            query: SQL query
            params: Query parameters

        Returns:
            Tuple[List[Dict[str, Any]], int]: Query results and row count

        Raises:
            APIError: If query execution fails
        """
        try:
            self.logger.info("Executing query: %s with params: %s", query, params)
            with self.engine.connect() as connection:
                result = connection.execute(text(query), params or {})
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
            raise APIError(error_message, status_code=500)
        except Exception as e:
            error_message = f"Unexpected error executing database query: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500)

    def execute_transaction(
        self, queries: List[Tuple[str, Optional[Dict[str, Any]]]]
    ) -> List[Union[List[Dict[str, Any]], int]]:
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
                    self.logger.info(
                        "Executing query in transaction: %s with params: %s", query, params
                    )
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
            raise APIError(error_message, status_code=500)
        except Exception as e:
            error_message = f"Unexpected error executing database transaction: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500)

    def get_connection_details(self, connection_name: str) -> Dict[str, Any]:
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
            raise APIError(error_message, status_code=500)

    def list_connections(self) -> List[Dict[str, Any]]:
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
            raise APIError(error_message, status_code=500)

    def add_connection(self, connection_data: Dict[str, Any]) -> int:
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
            raise APIError(error_message, status_code=500)

    def update_connection(self, connection_id: int, connection_data: Dict[str, Any]) -> None:
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
            raise APIError(error_message, status_code=500)

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
            raise APIError(error_message, status_code=500)
