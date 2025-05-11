"""
Unit tests for the core database module.
"""

import pytest
import sys
import os
import time
from unittest.mock import patch, MagicMock, call
from sqlalchemy.exc import OperationalError

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from core.database import (
    get_database_url,
    create_db_engine,
    get_engine,
    get_session_factory,
    configure_db_for_tests,
)


class TestCoreDatabase:
    """Tests for the core database module."""

    @pytest.fixture
    def reset_engine_state(self):
        """Reset the global engine and session factory state."""
        import core.database

        # Save original state
        orig_engine = core.database._engine
        orig_session_factory = core.database._session_factory

        # Reset for test
        core.database._engine = None
        core.database._session_factory = None

        # Run test
        yield

        # Restore original state
        core.database._engine = orig_engine
        core.database._session_factory = orig_session_factory

    @pytest.fixture
    def mock_settings(self):
        """Mock settings for database connection."""
        settings = MagicMock()
        settings.POSTGRES_USER = "test_user"
        settings.POSTGRES_PASSWORD = "test_password"
        settings.POSTGRES_HOST = "test_host"
        settings.POSTGRES_PORT = "5432"
        settings.POSTGRES_DATABASE = "test_db"
        return settings

    def test_get_database_url(self, mock_settings):
        """
        GIVEN the configured database settings
        WHEN get_database_url is called
        THEN it should return a properly formatted connection string
        """
        with patch("core.database.get_settings", return_value=mock_settings):
            url = get_database_url()
            assert url == "postgresql://test_user:test_password@test_host:5432/test_db"

    def test_create_db_engine_success(self, reset_engine_state):
        """
        GIVEN a valid database URL
        WHEN create_db_engine is called
        THEN it should return a SQLAlchemy engine
        """
        mock_engine = MagicMock()
        mock_conn = MagicMock()

        with patch("core.database.create_engine", return_value=mock_engine) as mock_create_engine, patch(
            "core.database.get_database_url", return_value="postgresql://user:pass@host/db"
        ):
            # Setup mock engine connection
            mock_engine.connect.return_value.__enter__.return_value = mock_conn

            # Call the function
            result = create_db_engine()

            # Verify results
            assert result == mock_engine
            mock_create_engine.assert_called_once()
            mock_engine.connect.assert_called_once()
            mock_conn.execute.assert_called_once()

    def test_create_db_engine_retry_success(self, reset_engine_state):
        """
        GIVEN a database that fails on first attempt but succeeds later
        WHEN create_db_engine is called
        THEN it should retry and eventually return a SQLAlchemy engine
        """
        mock_engine = MagicMock()
        mock_conn = MagicMock()

        with patch("core.database.create_engine", return_value=mock_engine) as mock_create_engine, patch(
            "core.database.get_database_url", return_value="postgresql://user:pass@host/db"
        ), patch("core.database.time.sleep") as mock_sleep:
            # Setup mock engine to fail on first connect but succeed on second
            mock_engine.connect.side_effect = [
                OperationalError("statement", {}, None),  # First call fails
                MagicMock(__enter__=lambda x: mock_conn, __exit__=lambda x, y, z, a: None),  # Second call succeeds
            ]

            # Call the function
            result = create_db_engine()

            # Verify results
            assert result == mock_engine
            assert mock_create_engine.call_count == 2
            assert mock_engine.connect.call_count == 2
            assert mock_sleep.call_count == 1
            mock_sleep.assert_called_with(2)  # Default delay

    def test_create_db_engine_all_retries_fail(self, reset_engine_state):
        """
        GIVEN a database that consistently fails to connect
        WHEN create_db_engine is called
        THEN it should retry the specified number of times and then raise OperationalError
        """
        with patch("core.database.create_engine") as mock_create_engine, patch(
            "core.database.get_database_url", return_value="postgresql://user:pass@host/db"
        ), patch("core.database.time.sleep") as mock_sleep:
            # Setup mock engine to always fail
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            error = OperationalError("statement", {}, None)
            mock_engine.connect.side_effect = error

            # Call the function and expect an exception
            with pytest.raises(OperationalError):
                create_db_engine(retries=3, delay=1)

            # Verify results
            assert mock_create_engine.call_count == 3
            assert mock_engine.connect.call_count == 3
            assert mock_sleep.call_count == 2  # Sleep called after first and second failures
            mock_sleep.assert_has_calls([call(1), call(1)])

    def test_create_db_engine_unexpected_error(self, reset_engine_state):
        """
        GIVEN a database connection that raises an unexpected error
        WHEN create_db_engine is called
        THEN it should not retry and just raise the error
        """
        with patch("core.database.create_engine") as mock_create_engine, patch(
            "core.database.get_database_url", return_value="postgresql://user:pass@host/db"
        ):
            # Setup mock engine to raise unexpected error
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            error = ValueError("Unexpected error")
            mock_engine.connect.side_effect = error

            # Call the function and expect an exception
            with pytest.raises(ValueError, match="Unexpected error"):
                create_db_engine()

            # Verify results
            assert mock_create_engine.call_count == 1
            assert mock_engine.connect.call_count == 1

    def test_get_engine_creates_new_engine(self, reset_engine_state):
        """
        GIVEN no existing engine
        WHEN get_engine is called
        THEN it should create and return a new engine
        """
        mock_engine = MagicMock()

        with patch("core.database.create_db_engine", return_value=mock_engine) as mock_create_db_engine:
            # Call the function
            result = get_engine()

            # Verify results
            assert result == mock_engine
            mock_create_db_engine.assert_called_once()

    def test_get_engine_returns_existing_engine(self, reset_engine_state):
        """
        GIVEN an existing engine
        WHEN get_engine is called multiple times
        THEN it should return the same engine without creating a new one
        """
        mock_engine = MagicMock()

        with patch("core.database.create_db_engine", return_value=mock_engine) as mock_create_db_engine:
            # Call the function twice
            first_result = get_engine()
            second_result = get_engine()

            # Verify results
            assert first_result == mock_engine
            assert second_result == mock_engine
            assert first_result is second_result  # Same instance
            mock_create_db_engine.assert_called_once()  # Only called once

    def test_get_session_factory_creates_new_factory(self, reset_engine_state):
        """
        GIVEN no existing session factory
        WHEN get_session_factory is called
        THEN it should create and return a new session factory
        """
        mock_engine = MagicMock()
        mock_session_factory = MagicMock()

        with patch("core.database.get_engine", return_value=mock_engine) as mock_get_engine, patch(
            "core.database.sessionmaker", return_value=mock_session_factory
        ) as mock_sessionmaker:
            # Call the function
            result = get_session_factory()

            # Verify results
            assert result == mock_session_factory
            mock_get_engine.assert_called_once()
            mock_sessionmaker.assert_called_once_with(autocommit=False, autoflush=False, bind=mock_engine)

    def test_get_session_factory_returns_existing_factory(self, reset_engine_state):
        """
        GIVEN an existing session factory
        WHEN get_session_factory is called multiple times
        THEN it should return the same factory without creating a new one
        """
        mock_engine = MagicMock()
        mock_session_factory = MagicMock()

        with patch("core.database.get_engine", return_value=mock_engine) as mock_get_engine, patch(
            "core.database.sessionmaker", return_value=mock_session_factory
        ) as mock_sessionmaker:
            # Call the function twice
            first_result = get_session_factory()
            second_result = get_session_factory()

            # Verify results
            assert first_result == mock_session_factory
            assert second_result == mock_session_factory
            assert first_result is second_result  # Same instance
            mock_get_engine.assert_called_once()  # Only called once
            mock_sessionmaker.assert_called_once()  # Only called once

    def test_configure_db_for_tests_postgresql(self, reset_engine_state):
        """
        GIVEN a PostgreSQL test database URL
        WHEN configure_db_for_tests is called
        THEN it should configure the engine and session factory correctly
        """
        mock_engine = MagicMock()
        mock_session_factory = MagicMock()
        test_db_url = "postgresql://test:test@localhost/test_db"

        with patch("core.database.create_engine", return_value=mock_engine) as mock_create_engine, patch(
            "core.database.sessionmaker", return_value=mock_session_factory
        ) as mock_sessionmaker, patch("core.database.event.listen") as mock_event_listen:
            # Call the function
            configure_db_for_tests(test_db_url)

            # Import to get the updated global variables
            import core.database

            # Verify results
            assert core.database._engine == mock_engine
            assert core.database._session_factory == mock_session_factory

            # Check engine creation
            mock_create_engine.assert_called_once()
            args, kwargs = mock_create_engine.call_args
            assert args[0] == test_db_url
            assert kwargs.get("connect_args") == {}  # No special connect_args for PostgreSQL
            assert kwargs.get("poolclass").__name__ == "QueuePool"  # Should be QueuePool for PostgreSQL

            # Check sessionmaker
            mock_sessionmaker.assert_called_once_with(autocommit=False, autoflush=False, bind=mock_engine)

            # Event listener should not be called for PostgreSQL
            mock_event_listen.assert_not_called()

    def test_configure_db_for_tests_sqlite(self, reset_engine_state):
        """
        GIVEN an SQLite test database URL
        WHEN configure_db_for_tests is called
        THEN it should configure the engine with SQLite-specific settings
        """
        mock_engine = MagicMock()
        mock_session_factory = MagicMock()
        test_db_url = "sqlite:///test.db"

        with patch("core.database.create_engine", return_value=mock_engine) as mock_create_engine, patch(
            "core.database.sessionmaker", return_value=mock_session_factory
        ) as mock_sessionmaker, patch("core.database.event.listen") as mock_event_listen:
            # Call the function
            configure_db_for_tests(test_db_url)

            # Import to get the updated global variables
            import core.database

            # Verify results
            assert core.database._engine == mock_engine
            assert core.database._session_factory == mock_session_factory

            # Check engine creation with SQLite-specific settings
            mock_create_engine.assert_called_once()
            args, kwargs = mock_create_engine.call_args
            assert args[0] == test_db_url
            assert kwargs.get("connect_args") == {"check_same_thread": False}  # SQLite-specific
            assert kwargs.get("poolclass").__name__ == "StaticPool"  # Should be StaticPool for SQLite

            # Check event listener for SQLite foreign keys
            mock_event_listen.assert_called_once()
            args, kwargs = mock_event_listen.call_args
            assert args[0] == mock_engine
            assert args[1] == "connect"
            # Third argument is a function that we can't directly compare
