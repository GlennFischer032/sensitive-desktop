import pytest
import sys
import os
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

# Add the src directory to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))


@pytest.fixture(scope="session")
def setup_test_db():
    """Set up test database tables."""
    # Import all models to ensure all are registered with Base
    from database.models.user import User, SocialAuthAssociation, PKCEState
    from database.models.connection import Connection
    from database.models.desktop_configuration import DesktopConfiguration, DesktopConfigurationAccess
    from database.models.storage_pvc import StoragePVC, StoragePVCAccess, ConnectionPVCMap
    from database.models.token import Token
    from schemas.base import Base

    # Create in-memory test database
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )

    # Enable foreign key support in SQLite
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    # Create tables
    Base.metadata.create_all(engine)

    # Create session factory
    TestSessionLocal = sessionmaker(bind=engine)

    # Return session factory
    return TestSessionLocal


@pytest.fixture(scope="function")
def test_db_session(db_session):
    """Get a test database session with tables created.

    This uses the db_session fixture from the main conftest.py
    """
    return db_session


@pytest.fixture(scope="function")
def mock_db_session(test_db_session):
    """Provide a mocked database session with tables for all API routes."""
    # Patch the get_db_session function to return our test session
    with patch("database.core.session.get_db_session") as mock:
        # Setup the context manager return value
        mock.return_value.__enter__.return_value = test_db_session

        # Also patch the auth module's get_db_session
        with patch("core.auth.get_db_session") as auth_mock:
            auth_mock.return_value.__enter__.return_value = test_db_session

            # Patch the with_db_session decorator to pass through
            with patch("database.core.session.with_db_session", lambda f: f):
                with patch("routes.user_routes.with_db_session", lambda f: f):
                    yield test_db_session
