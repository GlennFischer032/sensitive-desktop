"""
Unit tests for the DesktopConfigurationService class.
"""

import pytest
import sys
import os
from datetime import datetime
from unittest.mock import MagicMock, patch

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from services.desktop_configuration import DesktopConfigurationService
from services.connections import APIError, BadRequestError, NotFoundError
from database.models.desktop_configuration import DesktopConfiguration, DesktopConfigurationAccess


class TestDesktopConfigurationService:
    """Tests for the DesktopConfigurationService class."""

    @pytest.fixture
    def mock_user(self):
        """Create a mock user for testing."""
        user = MagicMock()
        user.username = "testuser"
        user.is_admin = False
        return user

    @pytest.fixture
    def mock_admin_user(self):
        """Create a mock admin user for testing."""
        user = MagicMock()
        user.username = "admin"
        user.is_admin = True
        return user

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session for testing."""
        return MagicMock()

    @pytest.fixture
    def mock_repository(self):
        """Mock the DesktopConfigurationRepository for testing."""
        with patch("services.desktop_configuration.DesktopConfigurationRepository") as mock:
            repo_instance = MagicMock()
            mock.return_value = repo_instance
            yield repo_instance

    @pytest.fixture
    def sample_config(self):
        """Create a sample desktop configuration."""
        config = MagicMock(spec=DesktopConfiguration)
        config.id = 1
        config.name = "test-config"
        config.description = "Test Configuration"
        config.image = "test/image:latest"
        config.created_at = datetime.utcnow()
        config.is_public = False
        config.created_by = "admin"
        config.min_cpu = 1
        config.max_cpu = 4
        config.min_ram = "4096Mi"
        config.max_ram = "16384Mi"
        return config

    def test_list_configurations_admin(self, mock_admin_user, mock_session, mock_repository, sample_config):
        """
        GIVEN an admin user and a mock repository
        WHEN list_configurations is called
        THEN it should return all configurations
        """
        # Setup
        service = DesktopConfigurationService()
        mock_repository.get_all_configurations.return_value = [sample_config]
        mock_repository.get_access_entries.return_value = []

        # Execute
        result = service.list_configurations(mock_admin_user, mock_session)

        # Verify
        assert "configurations" in result
        assert len(result["configurations"]) == 1
        assert result["configurations"][0]["id"] == 1
        assert result["configurations"][0]["name"] == "test-config"
        assert result["configurations"][0]["image"] == "test/image:latest"
        mock_repository.get_all_configurations.assert_called_once()

    def test_list_configurations_regular_user(self, mock_user, mock_session, mock_repository, sample_config):
        """
        GIVEN a regular user and a mock repository
        WHEN list_configurations is called
        THEN it should return configurations accessible to the user
        """
        # Setup
        service = DesktopConfigurationService()
        mock_repository.get_configurations_for_user.return_value = [sample_config]
        mock_repository.get_access_entries.return_value = []

        # Execute
        result = service.list_configurations(mock_user, mock_session)

        # Verify
        assert "configurations" in result
        assert len(result["configurations"]) == 1
        assert result["configurations"][0]["id"] == 1
        assert result["configurations"][0]["name"] == "test-config"
        mock_repository.get_configurations_for_user.assert_called_once_with("testuser")

    def test_list_configurations_exception(self, mock_user, mock_session, mock_repository):
        """
        GIVEN a mock repository that raises an exception
        WHEN list_configurations is called
        THEN it should wrap and re-raise the exception as APIError
        """
        # Setup
        service = DesktopConfigurationService()
        mock_repository.get_configurations_for_user.side_effect = Exception("Database error")

        # Execute and verify
        with pytest.raises(APIError) as excinfo:
            service.list_configurations(mock_user, mock_session)

        assert "Failed to list configurations" in str(excinfo.value)

    def test_create_configuration_success(self, mock_admin_user, mock_session, mock_repository, sample_config):
        """
        GIVEN valid configuration data
        WHEN create_configuration is called
        THEN it should create and return the new configuration
        """
        # Setup
        service = DesktopConfigurationService()
        mock_repository.get_by_name.return_value = None
        mock_repository.create_configuration.return_value = sample_config

        data = {
            "name": "test-config",
            "description": "Test Configuration",
            "image": "test/image:latest",
            "is_public": False,
            "min_cpu": 1,
            "max_cpu": 4,
            "min_ram": "4096Mi",
            "max_ram": "16384Mi",
            "allowed_users": ["user1", "user2"],
        }

        # Execute
        result = service.create_configuration(data, mock_admin_user, mock_session)

        # Verify
        assert "configuration" in result
        assert result["configuration"]["id"] == 1
        assert result["configuration"]["name"] == "test-config"
        mock_repository.create_configuration.assert_called_once()
        assert mock_repository.create_access.call_count == 2

    def test_create_configuration_missing_fields(self, mock_admin_user, mock_session, mock_repository):
        """
        GIVEN configuration data missing required fields
        WHEN create_configuration is called
        THEN it should raise BadRequestError
        """
        # Setup
        service = DesktopConfigurationService()

        # Data missing required image field
        data = {"name": "test-config"}

        # Execute and verify
        with pytest.raises(BadRequestError) as excinfo:
            service.create_configuration(data, mock_admin_user, mock_session)

        assert "Missing required fields" in str(excinfo.value)
        mock_repository.create_configuration.assert_not_called()

    def test_create_configuration_duplicate_name(self, mock_admin_user, mock_session, mock_repository, sample_config):
        """
        GIVEN configuration data with a name that already exists
        WHEN create_configuration is called
        THEN it should raise BadRequestError
        """
        # Setup
        service = DesktopConfigurationService()
        mock_repository.get_by_name.return_value = sample_config

        data = {"name": "test-config", "image": "test/image:latest"}

        # Execute and verify
        with pytest.raises(BadRequestError) as excinfo:
            service.create_configuration(data, mock_admin_user, mock_session)

        assert "already exists" in str(excinfo.value)
        mock_repository.create_configuration.assert_not_called()

    def test_update_configuration_success(self, mock_session, mock_repository, sample_config):
        """
        GIVEN valid update data and an existing configuration
        WHEN update_configuration is called
        THEN it should update and return the configuration
        """
        # Setup
        service = DesktopConfigurationService()
        mock_repository.get_by_id.return_value = sample_config
        mock_repository.get_by_name.return_value = None
        mock_repository.update_configuration.return_value = sample_config

        data = {
            "name": "updated-config",
            "description": "Updated Description",
            "image": "test/image:v2",
            "is_public": True,
            "allowed_users": [],
        }

        # Execute
        result = service.update_configuration(1, data, mock_session)

        # Verify
        assert "configuration" in result
        assert result["configuration"]["id"] == 1
        assert result["configuration"]["name"] == "test-config"
        mock_repository.update_configuration.assert_called_once()
        mock_repository.clear_access.assert_called_once_with(1)

    def test_update_configuration_not_found(self, mock_session, mock_repository):
        """
        GIVEN a non-existent configuration ID
        WHEN update_configuration is called
        THEN it should raise NotFoundError
        """
        # Setup
        service = DesktopConfigurationService()
        mock_repository.get_by_id.return_value = None

        data = {"name": "updated-config", "image": "test/image:v2"}

        # Execute and verify
        with pytest.raises(NotFoundError) as excinfo:
            service.update_configuration(999, data, mock_session)

        assert "not found" in str(excinfo.value)
        mock_repository.update_configuration.assert_not_called()

    def test_update_configuration_duplicate_name(self, mock_session, mock_repository, sample_config):
        """
        GIVEN update data with a name that belongs to another configuration
        WHEN update_configuration is called
        THEN it should raise BadRequestError
        """
        # Setup
        service = DesktopConfigurationService()
        mock_repository.get_by_id.return_value = sample_config

        # Create a different configuration with the same name
        other_config = MagicMock(spec=DesktopConfiguration)
        other_config.id = 2
        other_config.name = "updated-config"

        mock_repository.get_by_name.return_value = other_config

        data = {"name": "updated-config", "image": "test/image:v2"}

        # Execute and verify
        with pytest.raises(BadRequestError) as excinfo:
            service.update_configuration(1, data, mock_session)

        assert "already exists" in str(excinfo.value)
        mock_repository.update_configuration.assert_not_called()

    def test_get_configuration_admin(self, mock_admin_user, mock_session, mock_repository, sample_config):
        """
        GIVEN an admin user and an existing configuration
        WHEN get_configuration is called
        THEN it should return the configuration
        """
        # Setup
        service = DesktopConfigurationService()
        mock_repository.get_by_id.return_value = sample_config
        mock_repository.get_access_entries.return_value = []

        # Execute
        result = service.get_configuration(1, mock_admin_user, mock_session)

        # Verify
        assert "configuration" in result
        assert result["configuration"]["id"] == 1
        assert result["configuration"]["name"] == "test-config"
        mock_repository.get_by_id.assert_called_once_with(1)

    def test_get_configuration_regular_user(self, mock_user, mock_session, mock_repository, sample_config):
        """
        GIVEN a regular user and an accessible configuration
        WHEN get_configuration is called
        THEN it should return the configuration
        """
        # Setup
        service = DesktopConfigurationService()
        mock_repository.get_configurations_for_user.return_value = sample_config
        mock_repository.get_access_entries.return_value = []

        # Execute
        result = service.get_configuration(1, mock_user, mock_session)

        # Verify
        assert "configuration" in result
        assert result["configuration"]["id"] == 1
        assert result["configuration"]["name"] == "test-config"
        mock_repository.get_configurations_for_user.assert_called_once_with("testuser", 1)

    def test_get_configuration_not_found(self, mock_user, mock_session, mock_repository):
        """
        GIVEN a non-existent or inaccessible configuration
        WHEN get_configuration is called
        THEN it should raise NotFoundError
        """
        # Setup
        service = DesktopConfigurationService()
        mock_repository.get_configurations_for_user.return_value = None

        # Execute and verify
        with pytest.raises(NotFoundError) as excinfo:
            service.get_configuration(999, mock_user, mock_session)

        assert "not found or access denied" in str(excinfo.value)

    def test_delete_configuration_success(self, mock_session, mock_repository, sample_config):
        """
        GIVEN an existing configuration that is not in use
        WHEN delete_configuration is called
        THEN it should delete the configuration
        """
        # Setup
        service = DesktopConfigurationService()
        mock_repository.get_by_id.return_value = sample_config
        mock_repository.is_in_use.return_value = False

        # Execute
        result = service.delete_configuration(1, mock_session)

        # Verify
        assert "message" in result
        assert "deleted successfully" in result["message"]
        mock_repository.clear_access.assert_called_once_with(1)
        mock_repository.delete_configuration.assert_called_once_with(1)

    def test_delete_configuration_not_found(self, mock_session, mock_repository):
        """
        GIVEN a non-existent configuration ID
        WHEN delete_configuration is called
        THEN it should raise NotFoundError
        """
        # Setup
        service = DesktopConfigurationService()
        mock_repository.get_by_id.return_value = None

        # Execute and verify
        with pytest.raises(NotFoundError) as excinfo:
            service.delete_configuration(999, mock_session)

        assert "not found" in str(excinfo.value)
        mock_repository.delete_configuration.assert_not_called()

    def test_delete_configuration_in_use(self, mock_session, mock_repository, sample_config):
        """
        GIVEN a configuration that is in use by connections
        WHEN delete_configuration is called
        THEN it should raise BadRequestError
        """
        # Setup
        service = DesktopConfigurationService()
        mock_repository.get_by_id.return_value = sample_config
        mock_repository.is_in_use.return_value = True

        # Execute and verify
        with pytest.raises(BadRequestError) as excinfo:
            service.delete_configuration(1, mock_session)

        assert "being used by a connection" in str(excinfo.value)
        mock_repository.delete_configuration.assert_not_called()

    def test_get_configuration_access(self, mock_session, mock_repository, sample_config):
        """
        GIVEN an existing configuration
        WHEN get_configuration_access is called
        THEN it should return the users with access
        """
        # Setup
        service = DesktopConfigurationService()
        mock_repository.get_by_id.return_value = sample_config
        mock_repository.get_users_with_access.return_value = ["user1", "user2"]

        # Execute
        result = service.get_configuration_access(1, mock_session)

        # Verify
        assert "users" in result
        assert result["users"] == ["user1", "user2"]
        mock_repository.get_users_with_access.assert_called_once_with(1)

    def test_get_configuration_access_not_found(self, mock_session, mock_repository):
        """
        GIVEN a non-existent configuration ID
        WHEN get_configuration_access is called
        THEN it should raise NotFoundError
        """
        # Setup
        service = DesktopConfigurationService()
        mock_repository.get_by_id.return_value = None

        # Execute and verify
        with pytest.raises(NotFoundError) as excinfo:
            service.get_configuration_access(999, mock_session)

        assert "not found" in str(excinfo.value)
        mock_repository.get_users_with_access.assert_not_called()

    def test_list_accessible_configurations_admin(self, mock_admin_user, mock_session, mock_repository, sample_config):
        """
        GIVEN an admin user
        WHEN list_accessible_configurations is called
        THEN it should return all configurations
        """
        # Setup
        service = DesktopConfigurationService()
        mock_repository.get_all_configurations.return_value = [sample_config]

        # Execute
        result = service.list_accessible_configurations(mock_admin_user, mock_session)

        # Verify
        assert "configurations" in result
        assert result["configurations"] == [sample_config]
        mock_repository.get_all_configurations.assert_called_once()

    def test_list_accessible_configurations_regular_user(self, mock_user, mock_session, mock_repository, sample_config):
        """
        GIVEN a regular user
        WHEN list_accessible_configurations is called
        THEN it should return accessible configurations
        """
        # Setup
        service = DesktopConfigurationService()
        mock_repository.get_configurations_for_user.return_value = [sample_config]

        # Execute
        result = service.list_accessible_configurations(mock_user, mock_session)

        # Verify
        assert "configurations" in result
        assert result["configurations"] == [sample_config]
        mock_repository.get_configurations_for_user.assert_called_once_with("testuser")

    def test_list_accessible_configurations_exception(self, mock_user, mock_session, mock_repository):
        """
        GIVEN a repository that raises an exception
        WHEN list_accessible_configurations is called
        THEN it should wrap and re-raise the exception as APIError
        """
        # Setup
        service = DesktopConfigurationService()
        mock_repository.get_configurations_for_user.side_effect = Exception("Database error")

        # Execute and verify
        with pytest.raises(APIError) as excinfo:
            service.list_accessible_configurations(mock_user, mock_session)

        assert "Failed to list accessible configurations" in str(excinfo.value)
