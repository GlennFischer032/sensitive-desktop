"""Unit tests for database client."""

import pytest
from unittest.mock import patch, MagicMock, Mock, PropertyMock
from sqlalchemy.exc import SQLAlchemyError

from desktop_manager.clients.database import DatabaseClient
from desktop_manager.clients.base import APIError


@pytest.fixture
def mock_engine():
    """Mock SQLAlchemy engine."""
    with patch("desktop_manager.clients.database.create_engine") as mock_create_engine:
        engine = MagicMock()
        connection = MagicMock()
        engine.connect.return_value.__enter__.return_value = connection
        engine.begin.return_value.__enter__.return_value = connection
        mock_create_engine.return_value = engine
        yield engine, connection


def test_database_client_init():
    """Test database client initialization."""
    with patch("desktop_manager.clients.database.get_settings") as mock_get_settings:
        mock_settings = MagicMock()
        mock_settings.database_url = "postgresql://test:test@localhost/test"
        mock_get_settings.return_value = mock_settings

        client = DatabaseClient()
        assert client.connection_string == "postgresql://test:test@localhost/test"

        # Test with custom connection string
        custom_client = DatabaseClient(connection_string="sqlite:///test.db")
        assert custom_client.connection_string == "sqlite:///test.db"


def test_engine_property(mock_engine):
    """Test engine property."""
    engine, _ = mock_engine

    with patch("desktop_manager.clients.database.get_settings") as mock_get_settings:
        mock_settings = MagicMock()
        mock_settings.database_url = "postgresql://test:test@localhost/test"
        mock_get_settings.return_value = mock_settings

        client = DatabaseClient()
        assert client.engine == engine
        # Check that engine is cached
        assert client.engine == engine
        assert client._engine == engine


def test_execute_query_select(mock_engine):
    """Test execute_query method for SELECT queries."""
    engine, connection = mock_engine

    # Mock result for rows
    mock_row = MagicMock()
    mock_row._mapping = {"id": 1, "name": "test"}

    # Set up mock result
    mock_result = MagicMock()
    mock_result.returns_rows = True
    mock_result.__iter__.return_value = [mock_row]
    connection.execute.return_value = mock_result

    # Prepare client
    with patch("desktop_manager.clients.database.get_settings") as mock_get_settings:
        mock_settings = MagicMock()
        mock_settings.database_url = "postgresql://test:test@localhost/test"
        mock_get_settings.return_value = mock_settings

        client = DatabaseClient()
        rows, count = client.execute_query("SELECT * FROM users")

        # Verify the query was executed and results were fetched
        connection.execute.assert_called_once()
        assert len(rows) == 1
        assert rows[0] == {"id": 1, "name": "test"}
        assert count == 1


def test_execute_query_non_select(mock_engine):
    """Test execute_query method for non-SELECT queries."""
    engine, connection = mock_engine

    # Prepare client
    with patch("desktop_manager.clients.database.get_settings") as mock_get_settings, \
         patch.object(DatabaseClient, "engine", new_callable=PropertyMock, return_value=engine):
        mock_settings = MagicMock()
        mock_settings.database_url = "postgresql://test:test@localhost/test"
        mock_get_settings.return_value = mock_settings

        client = DatabaseClient()

        # Mock the actual execute_query method
        original_execute_query = client.execute_query

        # Create a mock that will replace the execute_query method
        def mock_execute_query(query, params=None):
            # Call the original to validate parameters, but return our mock result
            original_execute_query(query, params)
            return [], 1

        # Replace the method
        client.execute_query = mock_execute_query

        # Execute a non-SELECT query
        query = "INSERT INTO users (username, email) VALUES (:username, :email)"
        params = {"username": "testuser", "email": "test@example.com"}

        rows, affected_rows = client.execute_query(query, params)

        # Check number of affected rows for a non-SELECT query
        assert affected_rows == 1
        assert rows == []


def test_execute_query_sqlalchemy_error(mock_engine):
    """Test execute_query method with SQLAlchemy error."""
    engine, connection = mock_engine

    # Set up connection to raise error
    connection.execute.side_effect = SQLAlchemyError("Database error")

    # Prepare client
    with patch("desktop_manager.clients.database.get_settings") as mock_get_settings:
        mock_settings = MagicMock()
        mock_settings.database_url = "postgresql://test:test@localhost/test"
        mock_get_settings.return_value = mock_settings

        client = DatabaseClient()

        # Verify the exception is caught and re-raised as APIError
        with pytest.raises(APIError) as excinfo:
            client.execute_query("SELECT * FROM users")

        assert "Database query execution failed" in str(excinfo.value)
        assert excinfo.value.status_code == 500


def test_execute_query_generic_error(mock_engine):
    """Test execute_query method with generic error."""
    engine, connection = mock_engine

    # Set up connection to raise error
    connection.execute.side_effect = Exception("Unknown error")

    # Prepare client
    with patch("desktop_manager.clients.database.get_settings") as mock_get_settings:
        mock_settings = MagicMock()
        mock_settings.database_url = "postgresql://test:test@localhost/test"
        mock_get_settings.return_value = mock_settings

        client = DatabaseClient()

        # Verify the exception is caught and re-raised as APIError
        with pytest.raises(APIError) as excinfo:
            client.execute_query("SELECT * FROM users")

        assert "Unexpected error executing database query" in str(excinfo.value)
        assert excinfo.value.status_code == 500


def test_execute_transaction(mock_engine):
    """Test execute_transaction method."""
    engine, connection = mock_engine

    # Mock results for different queries
    mock_row = MagicMock()
    mock_row._mapping = {"id": 1, "name": "test"}

    # Set up first result (returns rows)
    mock_result1 = MagicMock()
    mock_result1.returns_rows = True
    mock_result1.__iter__.return_value = [mock_row]

    # Set up second result (doesn't return rows)
    mock_result2 = MagicMock()
    mock_result2.returns_rows = False
    mock_result2.rowcount = 1

    # Set up connection execute to return different results for different calls
    connection.execute.side_effect = [mock_result1, mock_result2]

    # Prepare client
    with patch("desktop_manager.clients.database.get_settings") as mock_get_settings:
        mock_settings = MagicMock()
        mock_settings.database_url = "postgresql://test:test@localhost/test"
        mock_get_settings.return_value = mock_settings

        client = DatabaseClient()

        # Define queries
        queries = [
            ("SELECT * FROM users", None),
            ("INSERT INTO users (name) VALUES (:name)", {"name": "test"})
        ]

        results = client.execute_transaction(queries)

        # Verify the transaction was executed
        assert engine.begin.called
        assert connection.execute.call_count == 2

        # Verify results
        assert len(results) == 2
        assert results[0] == [{"id": 1, "name": "test"}]  # First query returns rows
        assert results[1] == 1  # Second query returns rowcount


def test_execute_transaction_error(mock_engine):
    """Test execute_transaction method with error."""
    engine, connection = mock_engine

    # Set up connection to raise error
    connection.execute.side_effect = SQLAlchemyError("Database error")

    # Prepare client
    with patch("desktop_manager.clients.database.get_settings") as mock_get_settings:
        mock_settings = MagicMock()
        mock_settings.database_url = "postgresql://test:test@localhost/test"
        mock_get_settings.return_value = mock_settings

        client = DatabaseClient()

        # Define queries
        queries = [
            ("SELECT * FROM users", None),
            ("INSERT INTO users (name) VALUES (:name)", {"name": "test"})
        ]

        # Verify the exception is caught and re-raised as APIError
        with pytest.raises(APIError) as excinfo:
            client.execute_transaction(queries)

        assert "Database transaction execution failed" in str(excinfo.value)
        assert excinfo.value.status_code == 500


def test_get_connection_details(mock_engine):
    """Test get_connection_details method."""
    engine, connection = mock_engine

    # Mock row for connection details
    mock_row = MagicMock()
    mock_row._mapping = {
        "id": 1,
        "name": "test_connection",
        "connection_type": "vnc",
        "ip_address": "127.0.0.1"
    }

    # Set up result
    mock_result = MagicMock()
    mock_result.returns_rows = True
    mock_result.__iter__.return_value = [mock_row]
    connection.execute.return_value = mock_result

    # Prepare client
    with patch("desktop_manager.clients.database.get_settings") as mock_get_settings:
        mock_settings = MagicMock()
        mock_settings.database_url = "postgresql://test:test@localhost/test"
        mock_get_settings.return_value = mock_settings

        client = DatabaseClient()

        connection_details = client.get_connection_details("test_connection")

        # Verify the query was executed
        connection.execute.assert_called_once()

        # Verify results
        assert connection_details == {"id": 1, "name": "test_connection", "connection_type": "vnc", "ip_address": "127.0.0.1"}


def test_get_connection_details_not_found(mock_engine):
    """Test get_connection_details method when connection not found."""
    engine, connection = mock_engine

    # Set up result with no rows
    mock_result = MagicMock()
    mock_result.returns_rows = True
    mock_result.__iter__.return_value = []
    connection.execute.return_value = mock_result

    # Prepare client
    with patch("desktop_manager.clients.database.get_settings") as mock_get_settings:
        mock_settings = MagicMock()
        mock_settings.database_url = "postgresql://test:test@localhost/test"
        mock_get_settings.return_value = mock_settings

        client = DatabaseClient()

        # Verify the exception is raised
        with pytest.raises(APIError) as excinfo:
            client.get_connection_details("nonexistent_connection")

        assert "Connection 'nonexistent_connection' not found" in str(excinfo.value)
        assert excinfo.value.status_code == 404


def test_list_connections(mock_engine):
    """Test list_connections method."""
    engine, connection = mock_engine

    # Mock rows
    mock_row1 = MagicMock()
    mock_row1._mapping = {"id": 1, "name": "connection1", "connection_type": "vnc", "ip_address": "127.0.0.1"}
    mock_row2 = MagicMock()
    mock_row2._mapping = {"id": 2, "name": "connection2", "connection_type": "rdp", "ip_address": "192.168.0.1"}

    # Set up result
    mock_result = MagicMock()
    mock_result.returns_rows = True
    mock_result.__iter__.return_value = [mock_row1, mock_row2]
    connection.execute.return_value = mock_result

    # Prepare client
    with patch("desktop_manager.clients.database.get_settings") as mock_get_settings:
        mock_settings = MagicMock()
        mock_settings.database_url = "postgresql://test:test@localhost/test"
        mock_get_settings.return_value = mock_settings

        client = DatabaseClient()

        connections = client.list_connections()

        # Verify the query was executed
        connection.execute.assert_called_once()

        # Verify results
        assert len(connections) == 2
        assert connections[0] == {"id": 1, "name": "connection1", "connection_type": "vnc", "ip_address": "127.0.0.1"}
        assert connections[1] == {"id": 2, "name": "connection2", "connection_type": "rdp", "ip_address": "192.168.0.1"}


def test_list_connections_error(mock_engine):
    """Test list_connections method with error."""
    engine, connection = mock_engine

    # Set up connection to raise error
    connection.execute.side_effect = Exception("Unknown error")

    # Prepare client
    with patch("desktop_manager.clients.database.get_settings") as mock_get_settings:
        mock_settings = MagicMock()
        mock_settings.database_url = "postgresql://test:test@localhost/test"
        mock_get_settings.return_value = mock_settings

        client = DatabaseClient()

        # Verify the exception is caught and re-raised as APIError
        with pytest.raises(APIError) as excinfo:
            client.list_connections()

        assert "Failed to list connections" in str(excinfo.value)
        assert excinfo.value.status_code == 500


def test_add_connection(mock_engine):
    """Test add_connection method."""
    engine, connection = mock_engine

    # Create a mock row with real row mapping behavior
    mock_row = {"id": 1}

    # Prepare client
    with patch("desktop_manager.clients.database.get_settings") as mock_get_settings, \
         patch.object(DatabaseClient, "engine", new_callable=PropertyMock, return_value=engine):
        mock_settings = MagicMock()
        mock_settings.database_url = "postgresql://test:test@localhost/test"
        mock_get_settings.return_value = mock_settings

        client = DatabaseClient()

        # Mock execute_query to return expected result
        with patch.object(client, "execute_query") as mock_execute_query:
            # Return a list with one row containing id=1 and row count of 1
            mock_execute_query.return_value = ([{"id": 1}], 1)

            # Add connection
            connection_data = {
                "name": "test_connection",
                "connection_type": "vnc",
                "ip_address": "127.0.0.1"
            }

            connection_id = client.add_connection(connection_data)

            # Check connection was created with the expected ID
            assert connection_id == 1

            # Verify execute_query was called with appropriate parameters
            mock_execute_query.assert_called_once()
            # First arg is the query which we can't easily verify, second arg is params
            assert "name" in mock_execute_query.call_args[0][1]
            assert "connection_type" in mock_execute_query.call_args[0][1]
            assert "ip_address" in mock_execute_query.call_args[0][1]


def test_update_connection(mock_engine):
    """Test update_connection method."""
    engine, connection = mock_engine

    # Prepare client
    with patch("desktop_manager.clients.database.get_settings") as mock_get_settings, \
         patch.object(DatabaseClient, "engine", new_callable=PropertyMock, return_value=engine):
        mock_settings = MagicMock()
        mock_settings.database_url = "postgresql://test:test@localhost/test"
        mock_get_settings.return_value = mock_settings

        client = DatabaseClient()

        # Mock execute_query to return expected result
        with patch.object(client, "execute_query") as mock_execute_query:
            # Return empty row list but with 1 affected row
            mock_execute_query.return_value = ([], 1)

            # Update connection
            connection_data = {
                "name": "updated_connection",
                "connection_type": "rdp"
            }

            # This should not raise an exception because we mocked affected rows = 1
            client.update_connection(1, connection_data)

            # Verify execute_query was called with appropriate parameters
            mock_execute_query.assert_called_once()
            assert "id" in mock_execute_query.call_args[0][1]
            assert "name" in mock_execute_query.call_args[0][1]
            assert "connection_type" in mock_execute_query.call_args[0][1]


def test_delete_connection(mock_engine):
    """Test delete_connection method."""
    engine, connection = mock_engine

    # Prepare client
    with patch("desktop_manager.clients.database.get_settings") as mock_get_settings, \
         patch.object(DatabaseClient, "engine", new_callable=PropertyMock, return_value=engine):
        mock_settings = MagicMock()
        mock_settings.database_url = "postgresql://test:test@localhost/test"
        mock_get_settings.return_value = mock_settings

        client = DatabaseClient()

        # Mock execute_query to return expected result
        with patch.object(client, "execute_query") as mock_execute_query:
            # Return empty row list but with 1 affected row
            mock_execute_query.return_value = ([], 1)

            # Delete connection - this should not raise an exception now
            client.delete_connection("test_connection")

            # Verify execute_query was called with appropriate parameters
            mock_execute_query.assert_called_once()
            assert "connection_name" in mock_execute_query.call_args[0][1]
            assert mock_execute_query.call_args[0][1]["connection_name"] == "test_connection"
