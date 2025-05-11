import pytest
import sys
import os
from unittest.mock import MagicMock, patch
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime, timedelta

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from database.repositories.connection import ConnectionRepository
from database.models.connection import Connection
from database.models.desktop_configuration import DesktopConfiguration
from database.models.user import User
from database.models.storage_pvc import StoragePVC, ConnectionPVCMap
from core.exceptions import DatabaseError


@pytest.fixture
def mock_session():
    """Create a mock session for testing."""
    session = MagicMock()

    # Configure query filtering
    mock_query = MagicMock()
    session.query.return_value = mock_query
    mock_query.filter.return_value = mock_query
    mock_query.filter_by.return_value = mock_query
    mock_query.join.return_value = mock_query
    mock_query.all.return_value = []
    mock_query.first.return_value = None
    mock_query.count.return_value = 0
    mock_query.order_by.return_value = mock_query

    return session


@pytest.fixture
def connection_repository(mock_session):
    """Create a connection repository with a mock session."""
    return ConnectionRepository(mock_session)


@pytest.fixture
def sample_connection():
    """Create a sample connection for testing."""
    connection = Connection()
    connection.id = 1
    connection.name = "test-connection"
    connection.hostname = "test-host"
    connection.port = 5900
    connection.created_by = "test-user"
    connection.is_stopped = False
    connection.persistent_home = True
    connection.desktop_configuration_id = 1
    connection.created_at = datetime.utcnow()
    connection.updated_at = datetime.utcnow()

    return connection


def test_get_by_id(connection_repository, mock_session, sample_connection):
    """Test getting a connection by ID."""
    # Reset mock to clear any previous calls
    mock_session.query.reset_mock()
    mock_session.query().filter.return_value.first.return_value = sample_connection

    result = connection_repository.get_by_id(1)

    assert result == sample_connection

    # First call should be with Connection
    mock_session.query.assert_called_with(Connection)


def test_get_by_name(connection_repository, mock_session, sample_connection):
    """Test getting a connection by name."""
    # Reset mock to clear any previous calls
    mock_session.query.reset_mock()
    mock_session.query().filter.return_value.first.return_value = sample_connection

    result = connection_repository.get_by_name("test-connection")

    assert result == sample_connection

    # First call should be with Connection
    mock_session.query.assert_called_with(Connection)


def test_get_connections_by_creator(connection_repository, mock_session, sample_connection):
    """Test getting connections by creator."""
    # Reset mock to clear any previous calls
    mock_session.query.reset_mock()
    mock_session.query().filter.return_value.order_by.return_value.all.return_value = [sample_connection]

    result = connection_repository.get_connections_by_creator("test-user")

    assert len(result) == 1
    assert result[0] == sample_connection

    # First call should be with Connection
    mock_session.query.assert_called_with(Connection)


def test_get_all_connections(connection_repository, mock_session, sample_connection):
    """Test getting all connections."""
    # Reset mock to clear any previous calls
    mock_session.query.reset_mock()
    mock_session.query().order_by.return_value.all.return_value = [sample_connection]

    result = connection_repository.get_all_connections()

    assert len(result) == 1
    assert result[0] == sample_connection

    # First call should be with Connection
    mock_session.query.assert_called_with(Connection)


def test_create_connection(connection_repository, mock_session):
    """Test creating a connection."""
    # Setup data for creating a connection
    connection_data = {
        "name": "test-connection",
        "hostname": "test-host",
        "port": 5900,
        "created_by": "test-user",
        "is_stopped": False,
        "persistent_home": True,
        "desktop_configuration_id": 1,
        "vnc_password": "password123",
    }

    # Configure mock for create() method
    mock_session.add.return_value = None
    mock_session.commit.return_value = None

    # Create a connection
    connection_repository.create_connection(connection_data)

    # Verify session.add was called
    mock_session.add.assert_called_once()
    mock_session.commit.assert_called_once()

    # Check the connection passed to add()
    connection = mock_session.add.call_args[0][0]
    assert isinstance(connection, Connection)
    assert connection.name == "test-connection"
    assert connection.hostname == "test-host"
    assert connection.port == 5900
    assert connection.created_by == "test-user"
    assert connection.is_stopped is False
    assert connection.persistent_home is True
    assert connection.desktop_configuration_id == 1


def test_update_connection(connection_repository, mock_session, sample_connection):
    """Test updating a connection."""
    # Reset mock to clear any previous calls
    mock_session.query.reset_mock()
    mock_session.query().filter.return_value.first.return_value = sample_connection

    update_data = {
        "is_stopped": True,
        "persistent_home": False,
        "hostname": "new-host",
        "port": 5901,
        "vnc_password": "newpassword123",
    }

    result = connection_repository.update_connection(1, update_data)

    assert result == sample_connection
    assert result.is_stopped is True
    assert result.persistent_home is False
    assert result.hostname == "new-host"
    assert result.port == 5901

    # First call should be with Connection
    mock_session.query.assert_called_with(Connection)


def test_delete_connection(connection_repository, mock_session, sample_connection):
    """Test deleting a connection."""
    # Reset mock to clear any previous calls
    mock_session.query.reset_mock()
    mock_session.query().filter.return_value.first.return_value = sample_connection

    result = connection_repository.delete_connection(1)

    assert result is True
    mock_session.delete.assert_called_once_with(sample_connection)
    mock_session.commit.assert_called_once()

    # First call should be with Connection
    mock_session.query.assert_called_with(Connection)


def test_delete_connection_not_found(connection_repository, mock_session):
    """Test deleting a connection that doesn't exist."""
    # Reset mock to clear any previous calls
    mock_session.query.reset_mock()
    mock_session.query().filter.return_value.first.return_value = None

    result = connection_repository.delete_connection(999)

    assert result is False
    mock_session.delete.assert_not_called()

    # First call should be with Connection
    mock_session.query.assert_called_with(Connection)


def test_get_connections_for_user(connection_repository, mock_session, sample_connection):
    """Test getting connections for a user."""
    # Reset mock to clear any previous calls
    mock_session.query.reset_mock()
    mock_session.query().filter.return_value.order_by.return_value.all.return_value = [sample_connection]

    result = connection_repository.get_connections_for_user("test-user")

    assert len(result) == 1
    assert result[0] == sample_connection

    # First call should be with Connection
    mock_session.query.assert_called_with(Connection)


def test_map_connection_to_pvc(connection_repository, mock_session):
    """Test mapping a connection to a PVC."""
    # Reset mock to clear any previous calls
    mock_session.add.reset_mock()
    mock_session.commit.reset_mock()

    result = connection_repository.map_connection_to_pvc(1, 2)

    # Verify session.add was called
    mock_session.add.assert_called_once()
    mock_session.commit.assert_called_once()

    # Check that a ConnectionPVCMap was created
    mapping = mock_session.add.call_args[0][0]
    assert isinstance(mapping, ConnectionPVCMap)
    assert mapping.connection_id == 1
    assert mapping.pvc_id == 2


def test_unmap_connection_pvc(connection_repository, mock_session):
    """Test unmapping a connection from a PVC."""
    # Create a mock mapping
    mapping = ConnectionPVCMap()
    mapping.id = 1
    mapping.connection_id = 1
    mapping.pvc_id = 2

    # Reset mock to clear any previous calls
    mock_session.query.reset_mock()
    mock_session.query().filter.return_value.first.return_value = mapping

    result = connection_repository.unmap_connection_pvc(1)

    assert result is True
    mock_session.delete.assert_called_once_with(mapping)
    mock_session.commit.assert_called_once()

    # First call should be with ConnectionPVCMap
    mock_session.query.assert_called_with(ConnectionPVCMap)


def test_is_pvc_in_use(connection_repository, mock_session):
    """Test checking if a PVC is in use."""
    # Reset mock to clear any previous calls
    mock_session.query.reset_mock()

    # Test when PVC is not in use
    mock_session.query().filter.return_value.count.return_value = 0
    result = connection_repository.is_pvc_in_use(1)
    assert result is False

    # Test when PVC is in use
    mock_session.query().filter.return_value.count.return_value = 1
    result = connection_repository.is_pvc_in_use(1)
    assert result is True

    # First call should be with ConnectionPVCMap
    mock_session.query.assert_called_with(ConnectionPVCMap)
