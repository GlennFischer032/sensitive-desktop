"""
Unit tests for the DesktopConfigurationRepository class.
"""

import pytest
import sys
import os
from datetime import datetime
from unittest.mock import MagicMock, patch, create_autospec, ANY

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from database.repositories.desktop_configuration import DesktopConfigurationRepository
from database.models.desktop_configuration import DesktopConfiguration, DesktopConfigurationAccess
from database.models.connection import Connection
from sqlalchemy import or_


class TestDesktopConfigurationRepository:
    """Tests for the DesktopConfigurationRepository class."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session for testing."""
        session = MagicMock()
        query = MagicMock()
        session.query.return_value = query
        query.filter.return_value = query
        query.order_by.return_value = query
        return session

    @pytest.fixture
    def repository(self, mock_session):
        """Create a DesktopConfigurationRepository instance with a mock session."""
        return DesktopConfigurationRepository(mock_session)

    @pytest.fixture
    def sample_config(self):
        """Create a sample desktop configuration."""
        config = MagicMock(spec=DesktopConfiguration)
        config.id = 1
        config.name = "test-config"
        config.description = "Test Configuration"
        config.image = "test/image:latest"
        config.created_at = datetime.now()
        config.is_public = False
        config.created_by = "admin"
        config.min_cpu = 1
        config.max_cpu = 4
        config.min_ram = "4096Mi"
        config.max_ram = "16384Mi"
        return config

    @pytest.fixture
    def sample_connection(self):
        """Create a sample connection."""
        connection = MagicMock(spec=Connection)
        connection.id = 1
        connection.name = "test-connection"
        connection.desktop_configuration_id = 1
        return connection

    def test_get_by_name(self, repository, mock_session, sample_config):
        """
        GIVEN a repository and a configuration name
        WHEN get_by_name is called
        THEN it should query the database with the correct filter
        """
        # Set up the mock to return the sample config
        mock_session.query.return_value.filter.return_value.first.return_value = sample_config

        # Call the method
        result = repository.get_by_name("test-config")

        # Verify the result and interactions
        assert result == sample_config
        mock_session.query.assert_called_once()
        mock_session.query.return_value.filter.assert_called_once()
        mock_session.query.return_value.filter.return_value.first.assert_called_once()

    def test_get_by_id(self, repository, mock_session, sample_config):
        """
        GIVEN a repository and a configuration ID
        WHEN get_by_id is called
        THEN it should query the database with the correct filter
        """
        # Set up the mock to return the sample config
        mock_session.query.return_value.filter.return_value.first.return_value = sample_config

        # Call the method
        result = repository.get_by_id(1)

        # Verify the result and interactions
        assert result == sample_config
        mock_session.query.assert_called_once()
        mock_session.query.return_value.filter.assert_called_once()
        mock_session.query.return_value.filter.return_value.first.assert_called_once()

    def test_create_configuration(self, repository, mock_session):
        """
        GIVEN a repository and configuration data
        WHEN create_configuration is called
        THEN it should create a new configuration with correct attributes
        """
        # Set up the mock for the create method
        with patch.object(repository, "create") as mock_create:
            mock_create.return_value = MagicMock(spec=DesktopConfiguration)

            # Prepare test data
            config_data = {
                "name": "test-config",
                "description": "Test Configuration",
                "image": "test/image:latest",
                "created_by": "admin",
                "is_public": True,
                "min_cpu": 2,
                "max_cpu": 8,
                "min_ram": "8192Mi",
                "max_ram": "32768Mi",
            }

            # Call the method
            result = repository.create_configuration(config_data)

            # Verify that create was called with a DesktopConfiguration object
            mock_create.assert_called_once()
            created_config = mock_create.call_args[0][0]
            assert isinstance(created_config, DesktopConfiguration)
            assert created_config.name == "test-config"
            assert created_config.description == "Test Configuration"
            assert created_config.image == "test/image:latest"
            assert created_config.created_by == "admin"
            assert created_config.is_public is True
            assert created_config.min_cpu == 2
            assert created_config.max_cpu == 8
            assert created_config.min_ram == "8192Mi"
            assert created_config.max_ram == "32768Mi"

    def test_create_configuration_with_minimal_data(self, repository, mock_session):
        """
        GIVEN a repository and minimal configuration data
        WHEN create_configuration is called
        THEN it should create a new configuration with default values
        """
        # Set up the mock for the create method
        with patch.object(repository, "create") as mock_create:
            mock_create.return_value = MagicMock(spec=DesktopConfiguration)

            # Prepare minimal test data
            config_data = {
                "name": "test-config",
                "image": "test/image:latest",
                "created_by": "admin",
            }

            # Call the method
            result = repository.create_configuration(config_data)

            # Verify that create was called with a DesktopConfiguration object
            mock_create.assert_called_once()
            created_config = mock_create.call_args[0][0]
            assert created_config.name == "test-config"
            assert created_config.image == "test/image:latest"
            assert created_config.created_by == "admin"
            assert created_config.description == ""  # Default value
            assert created_config.is_public is False  # Default value
            assert created_config.min_cpu == 1  # Default value
            assert created_config.max_cpu == 4  # Default value
            assert created_config.min_ram == "4096Mi"  # Default value
            assert created_config.max_ram == "16384Mi"  # Default value

    def test_update_configuration(self, repository, mock_session, sample_config):
        """
        GIVEN a repository and configuration data
        WHEN update_configuration is called
        THEN it should update the configuration with the new values
        """
        # Set up the mock to return the sample config when get_by_id is called
        with patch.object(repository, "get_by_id", return_value=sample_config):
            # Set up the mock for the update method
            with patch.object(repository, "update") as mock_update:
                # Prepare test data
                update_data = {
                    "name": "updated-config",
                    "description": "Updated Description",
                    "image": "test/image:v2",
                    "is_public": True,
                    "min_cpu": 2,
                    "max_cpu": 8,
                    "min_ram": "8192Mi",
                    "max_ram": "32768Mi",
                }

                # Call the method
                result = repository.update_configuration(1, update_data)

                # Verify the result and interactions
                assert result == sample_config
                repository.get_by_id.assert_called_once_with(1)
                mock_update.assert_called_once_with(sample_config)

                # Verify that the config was updated
                assert sample_config.name == "updated-config"
                assert sample_config.description == "Updated Description"
                assert sample_config.image == "test/image:v2"
                assert sample_config.is_public is True
                assert sample_config.min_cpu == 2
                assert sample_config.max_cpu == 8
                assert sample_config.min_ram == "8192Mi"
                assert sample_config.max_ram == "32768Mi"

    def test_update_configuration_not_found(self, repository, mock_session):
        """
        GIVEN a repository and a non-existent configuration ID
        WHEN update_configuration is called
        THEN it should return None
        """
        # Set up the mock to return None when get_by_id is called
        with patch.object(repository, "get_by_id", return_value=None):
            # Prepare test data
            update_data = {
                "name": "updated-config",
                "description": "Updated Description",
            }

            # Call the method
            result = repository.update_configuration(999, update_data)

            # Verify the result and interactions
            assert result is None
            repository.get_by_id.assert_called_once_with(999)

    def test_update_configuration_partial(self, repository, mock_session, sample_config):
        """
        GIVEN a repository and partial configuration data
        WHEN update_configuration is called
        THEN it should update only the specified fields
        """
        # Set up the mock to return the sample config when get_by_id is called
        with patch.object(repository, "get_by_id", return_value=sample_config):
            # Set up the mock for the update method
            with patch.object(repository, "update") as mock_update:
                # Prepare partial test data
                update_data = {
                    "name": "updated-config",
                    # Other fields are not included
                }

                # Store original values
                original_description = sample_config.description
                original_image = sample_config.image
                original_is_public = sample_config.is_public

                # Call the method
                result = repository.update_configuration(1, update_data)

                # Verify the result and interactions
                assert result == sample_config
                repository.get_by_id.assert_called_once_with(1)
                mock_update.assert_called_once_with(sample_config)

                # Verify that only the name was updated
                assert sample_config.name == "updated-config"
                assert sample_config.description == original_description
                assert sample_config.image == original_image
                assert sample_config.is_public == original_is_public

    def test_delete_configuration(self, repository, mock_session, sample_config):
        """
        GIVEN a repository and a configuration ID
        WHEN delete_configuration is called
        THEN it should delete the configuration
        """
        # Set up the mock to return the sample config when get_by_id is called
        with patch.object(repository, "get_by_id", return_value=sample_config):
            # Call the method
            result = repository.delete_configuration(1)

            # Verify the result and interactions
            assert result is True
            repository.get_by_id.assert_called_once_with(1)
            mock_session.delete.assert_called_once_with(sample_config)
            mock_session.commit.assert_called_once()

    def test_delete_configuration_not_found(self, repository, mock_session):
        """
        GIVEN a repository and a non-existent configuration ID
        WHEN delete_configuration is called
        THEN it should return False
        """
        # Set up the mock to return None when get_by_id is called
        with patch.object(repository, "get_by_id", return_value=None):
            # Call the method
            result = repository.delete_configuration(999)

            # Verify the result and interactions
            assert result is False
            repository.get_by_id.assert_called_once_with(999)
            mock_session.delete.assert_not_called()
            mock_session.commit.assert_not_called()

    def test_get_all_configurations(self, repository, mock_session, sample_config):
        """
        GIVEN a repository
        WHEN get_all_configurations is called
        THEN it should return all configurations
        """
        # Set up the mock to return a list of configurations
        mock_session.query.return_value.order_by.return_value.all.return_value = [sample_config]

        # Call the method
        result = repository.get_all_configurations()

        # Verify the result and interactions
        assert result == [sample_config]
        mock_session.query.assert_called_once()
        mock_session.query.return_value.order_by.assert_called_once()
        mock_session.query.return_value.order_by.return_value.all.assert_called_once()

    def test_get_configurations_for_user(self, repository, mock_session, sample_config):
        """
        GIVEN a repository and a username
        WHEN get_configurations_for_user is called
        THEN it should query for configurations accessible to the user
        """
        # Set up the mock to return a list of configurations
        mock_session.query.return_value.filter.return_value.order_by.return_value.all.return_value = [sample_config]

        # Call the method
        result = repository.get_configurations_for_user("testuser")

        # Verify the result and interactions
        assert result == [sample_config]
        # We don't check exactly what is passed to query() since it's a SQLAlchemy class
        assert mock_session.query.called
        assert mock_session.query.return_value.filter.called
        assert mock_session.query.return_value.filter.return_value.order_by.called
        assert mock_session.query.return_value.filter.return_value.order_by.return_value.all.called

    def test_get_configurations_created_by(self, repository, mock_session, sample_config):
        """
        GIVEN a repository and a username
        WHEN get_configurations_created_by is called
        THEN it should query for configurations created by the user
        """
        # Set up the mock to return a list of configurations
        mock_session.query.return_value.filter.return_value.order_by.return_value.all.return_value = [sample_config]

        # Call the method
        result = repository.get_configurations_created_by("admin")

        # Verify the result and interactions
        assert result == [sample_config]
        # We don't check exactly what is passed to query() since it's a SQLAlchemy class
        assert mock_session.query.called
        assert mock_session.query.return_value.filter.called
        assert mock_session.query.return_value.filter.return_value.order_by.called
        assert mock_session.query.return_value.filter.return_value.order_by.return_value.all.called

    def test_create_access(self, repository, mock_session):
        """
        GIVEN a repository, configuration ID, and username
        WHEN create_access is called
        THEN it should create a new access entry
        """
        # Call the method
        result = repository.create_access(1, "testuser")

        # Verify the interactions
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()

        # Verify the access entry was created with correct attributes
        created_access = mock_session.add.call_args[0][0]
        assert isinstance(created_access, DesktopConfigurationAccess)
        assert created_access.desktop_configuration_id == 1
        assert created_access.username == "testuser"

    def test_clear_access(self, repository, mock_session):
        """
        GIVEN a repository and a configuration ID
        WHEN clear_access is called
        THEN it should delete all access entries for the configuration
        """
        # Call the method
        repository.clear_access(1)

        # Verify the interactions
        assert mock_session.query.called
        assert mock_session.query.return_value.filter.called
        assert mock_session.query.return_value.filter.return_value.delete.called
        mock_session.commit.assert_called_once()

    def test_get_access_entries(self, repository, mock_session):
        """
        GIVEN a repository and a configuration ID
        WHEN get_access_entries is called
        THEN it should return all access entries for the configuration
        """
        # Create mock access entries
        access1 = MagicMock(spec=DesktopConfigurationAccess)
        access1.desktop_configuration_id = 1
        access1.username = "user1"

        access2 = MagicMock(spec=DesktopConfigurationAccess)
        access2.desktop_configuration_id = 1
        access2.username = "user2"

        # Set up the mock to return the access entries
        mock_session.query.return_value.filter.return_value.all.return_value = [access1, access2]

        # Call the method
        result = repository.get_access_entries(1)

        # Verify the result and interactions
        assert len(result) == 2
        assert result[0].username == "user1"
        assert result[1].username == "user2"
        assert mock_session.query.called
        assert mock_session.query.return_value.filter.called
        assert mock_session.query.return_value.filter.return_value.all.called

    def test_get_users_with_access(self, repository, mock_session):
        """
        GIVEN a repository and a configuration ID
        WHEN get_users_with_access is called
        THEN it should return all usernames with access to the configuration
        """
        # Create mock access entries
        access1 = MagicMock(spec=DesktopConfigurationAccess)
        access1.username = "user1"

        access2 = MagicMock(spec=DesktopConfigurationAccess)
        access2.username = "user2"

        # Set up the mock for get_access_entries to return the access entries
        with patch.object(repository, "get_access_entries", return_value=[access1, access2]):
            # Call the method
            result = repository.get_users_with_access(1)

            # Verify the result and interactions
            assert result == ["user1", "user2"]
            repository.get_access_entries.assert_called_once_with(1)

    def test_is_in_use_true(self, repository, mock_session, sample_connection):
        """
        GIVEN a repository and a configuration ID that is in use
        WHEN is_in_use is called
        THEN it should return True
        """
        # Set up the mock to return a count of 1 (in use)
        mock_session.query.return_value.filter.return_value.count.return_value = 1

        # Call the method
        result = repository.is_in_use(1)

        # Verify the result and interactions
        assert result is True
        assert mock_session.query.called
        assert mock_session.query.return_value.filter.called
        assert mock_session.query.return_value.filter.return_value.count.called

    def test_is_in_use_false(self, repository, mock_session):
        """
        GIVEN a repository and a configuration ID that is not in use
        WHEN is_in_use is called
        THEN it should return False
        """
        # Set up the mock to return a count of 0 (not in use)
        mock_session.query.return_value.filter.return_value.count.return_value = 0

        # Call the method
        result = repository.is_in_use(1)

        # Verify the result and interactions
        assert result is False
        assert mock_session.query.called
        assert mock_session.query.return_value.filter.called
        assert mock_session.query.return_value.filter.return_value.count.called

    def test_get_connections_for_configuration(self, repository, mock_session, sample_connection):
        """
        GIVEN a repository and a configuration ID
        WHEN get_connections_for_configuration is called
        THEN it should return all connections for the configuration
        """
        # Set up the mock to return a list of connections
        mock_session.query.return_value.filter.return_value.all.return_value = [sample_connection]

        # Call the method
        result = repository.get_connections_for_configuration(1)

        # Verify the result and interactions
        assert result == [sample_connection]
        assert mock_session.query.called
        assert mock_session.query.return_value.filter.called
        assert mock_session.query.return_value.filter.return_value.all.called
