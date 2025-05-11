"""
Tests for connections service.
"""

import pytest
import sys
import os
from datetime import datetime
from unittest.mock import patch, MagicMock, call
from services.connections import APIError, BadRequestError, NotFoundError, ForbiddenError, ConnectionsService

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))


class TestConnectionsService:
    """Tests for the ConnectionsService."""

    @pytest.fixture
    def settings_mock(self):
        """Mock settings."""
        with patch("services.connections.get_settings") as mock:
            settings = MagicMock()
            settings.DESKTOP_IMAGE = "test-image:latest"
            settings.NAMESPACE = "test"
            settings.EXTERNAL_GUACAMOLE_URL = "https://guacamole.example.com"
            mock.return_value = settings
            yield settings

    @pytest.fixture
    def connection_repo_mock(self):
        """Mock ConnectionRepository."""
        with patch("services.connections.ConnectionRepository") as mock:
            mock_instance = MagicMock()

            # Mock connection
            connection = MagicMock()
            connection.id = 1
            connection.name = "test-desktop"
            connection.created_at = datetime.utcnow()
            connection.created_by = "user1"
            connection.guacamole_connection_id = "abc123"
            connection.hostname = "test-desktop.example.com"
            connection.port = "5900"
            connection.encrypted_password = "encrypted_password"
            connection.persistent_home = True
            connection.is_stopped = False
            connection.desktop_configuration_id = 1
            connection.desktop_configuration = MagicMock()
            connection.desktop_configuration.name = "Test Config"

            # Mock PVCs
            pvc = MagicMock()
            pvc.id = 1
            pvc.name = "test-pvc"
            connection.pvcs = [pvc]

            # Configure mock methods
            mock_instance.get_by_name.return_value = connection
            mock_instance.get_by_id.return_value = connection
            mock_instance.create_connection.return_value = connection

            # For list_connections
            connection2 = MagicMock()
            connection2.id = 2
            connection2.name = "test-desktop-2"
            connection2.created_at = datetime.utcnow()
            connection2.created_by = "user2"
            connection2.persistent_home = True
            connection2.is_stopped = False
            connection2.desktop_configuration_id = 1
            connection2.desktop_configuration = MagicMock()
            connection2.desktop_configuration.name = "Test Config"
            connection2.pvcs = []

            mock_instance.get_all_connections.return_value = [connection, connection2]
            mock_instance.get_connections_by_creator.return_value = [connection]

            # Return mock
            mock.return_value = mock_instance
            yield mock_instance

    @pytest.fixture
    def storage_pvc_repo_mock(self):
        """Mock StoragePVCRepository."""
        with patch("services.connections.StoragePVCRepository") as mock:
            mock_instance = MagicMock()

            # Mock PVC
            pvc = MagicMock()
            pvc.id = 1
            pvc.name = "test-pvc"
            pvc.is_public = True

            # Mock access_permissions
            access = MagicMock()
            access.username = "user1"
            pvc.access_permissions = [access]

            # Configure mock methods
            mock_instance.get_by_name.return_value = pvc

            # Return mock
            mock.return_value = mock_instance
            yield mock_instance

    @pytest.fixture
    def desktop_config_repo_mock(self):
        """Mock DesktopConfigurationRepository."""
        with patch("services.connections.DesktopConfigurationRepository") as mock:
            mock_instance = MagicMock()

            # Mock desktop configuration
            config = MagicMock()
            config.id = 1
            config.name = "Test Config"
            config.image = "test-config-image:latest"
            config.min_cpu = 2
            config.max_cpu = 4
            config.min_ram = "4096Mi"
            config.max_ram = "8192Mi"

            # Mock user access
            user_access = MagicMock()
            user_access.username = "user1"
            config.users = [user_access]

            # Configure mock methods
            mock_instance.get_by_id.return_value = config

            # Return mock
            mock.return_value = mock_instance
            yield mock_instance

    @pytest.fixture
    def rancher_client_mock(self):
        """Mock RancherClient."""
        with patch("services.connections.client_factory") as factory_mock:
            rancher_client = MagicMock()

            # Configure mock methods
            rancher_client.install.return_value = None
            rancher_client.check_vnc_ready.return_value = True
            rancher_client.uninstall.return_value = None
            rancher_client.check_release_uninstalled.return_value = True

            factory_mock.get_rancher_client.return_value = rancher_client
            yield rancher_client

    @pytest.fixture
    def guacamole_client_mock(self):
        """Mock GuacamoleClient."""
        with patch("services.connections.client_factory") as factory_mock:
            guacamole_client = MagicMock()

            # Configure mock methods
            guacamole_client.json_auth_login.return_value = "mock-jwt-token"

            factory_mock.get_guacamole_client.return_value = guacamole_client
            yield guacamole_client

    @pytest.fixture
    def guacamole_json_auth_mock(self):
        """Mock GuacamoleJsonAuth."""
        with patch("services.connections.GuacamoleJsonAuth") as mock:
            mock_instance = MagicMock()

            # Configure mock methods
            mock_instance.generate_auth_data.return_value = "mock-auth-data"

            # Return mock
            mock.return_value = mock_instance
            yield mock_instance

    @pytest.fixture
    def decrypt_password_mock(self):
        """Mock decrypt_password."""
        with patch("services.connections.decrypt_password") as mock:
            mock.return_value = "decrypted_password"
            yield mock

    @pytest.fixture
    def generate_random_string_mock(self):
        """Mock generate_random_string."""
        with patch("services.connections.generate_random_string") as mock:
            mock.return_value = "random_string"
            yield mock

    @pytest.fixture
    def generate_unique_connection_name_mock(self):
        """Mock generate_unique_connection_name."""
        with patch("services.connections.generate_unique_connection_name") as mock:
            mock.return_value = "test-desktop"
            yield mock

    def test_validate_scale_up_input_success(self):
        """Test validating scale up input with valid data."""
        from services.connections import ConnectionsService

        # Arrange
        service = ConnectionsService()
        data = {"name": "test-desktop"}

        # Act - should not raise any exception
        service.validate_scale_up_input(data)

    def test_validate_scale_up_input_missing_name(self):
        """Test validating scale up input with missing name."""
        from services.connections import ConnectionsService

        # Arrange
        service = ConnectionsService()
        data = {"description": "Test desktop"}

        # Act & Assert
        with pytest.raises(BadRequestError) as excinfo:
            service.validate_scale_up_input(data)

        assert "Missing required field: name" in str(excinfo.value)

    def test_validate_scale_up_input_invalid_name(self):
        """Test validating scale up input with invalid name."""
        from services.connections import ConnectionsService

        # Arrange
        service = ConnectionsService()
        data = {"name": "Test_Desktop!"}  # Invalid name with uppercase and special chars

        # Act & Assert
        with pytest.raises(BadRequestError) as excinfo:
            service.validate_scale_up_input(data)

        assert "Connection name must start and end with an alphanumeric character" in str(excinfo.value)

    def test_validate_scale_up_input_name_too_long(self):
        """Test validating scale up input with name that is too long."""
        from services.connections import ConnectionsService

        # Arrange
        service = ConnectionsService()
        data = {"name": "abcdefghijklmnopqrst"}  # 20 characters, longer than 12

        # Act & Assert
        with pytest.raises(BadRequestError) as excinfo:
            service.validate_scale_up_input(data)

        assert "Connection name is too long" in str(excinfo.value)

    def test_validate_external_pvc_success(self, storage_pvc_repo_mock):
        """Test validating external PVC with valid data."""
        from services.connections import ConnectionsService

        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()
        external_pvc = "test-pvc"

        # Act
        result = service.validate_external_pvc(external_pvc, current_user, session)

        # Assert
        assert result == 1  # The PVC ID
        storage_pvc_repo_mock.get_by_name.assert_called_once_with(external_pvc)

    def test_validate_external_pvc_not_found(self, storage_pvc_repo_mock):
        """Test validating external PVC that doesn't exist."""
        from services.connections import ConnectionsService

        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()
        external_pvc = "nonexistent-pvc"

        # Setup mock to return None
        storage_pvc_repo_mock.get_by_name.return_value = None

        # Act & Assert
        with pytest.raises(NotFoundError) as excinfo:
            service.validate_external_pvc(external_pvc, current_user, session)

        assert f"PVC '{external_pvc}' not found" in str(excinfo.value)

    def test_validate_external_pvc_no_permission(self, storage_pvc_repo_mock):
        """Test validating external PVC without permission."""
        from services.connections import ConnectionsService

        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user2"  # Different user
        current_user.is_admin = False
        session = MagicMock()
        external_pvc = "test-pvc"

        # Setup mock for non-public PVC
        pvc = MagicMock()
        pvc.id = 1
        pvc.name = "test-pvc"
        pvc.is_public = False

        # Mock access_permissions for user1 only
        access = MagicMock()
        access.username = "user1"
        pvc.access_permissions = [access]

        storage_pvc_repo_mock.get_by_name.return_value = pvc

        # Act & Assert
        with pytest.raises(ForbiddenError) as excinfo:
            service.validate_external_pvc(external_pvc, current_user, session)

        assert "You do not have permission to use this PVC" in str(excinfo.value)

    def test_get_desktop_configuration_with_id(self, desktop_config_repo_mock):
        """Test getting desktop configuration with ID."""
        from services.connections import ConnectionsService

        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()
        config_id = 1

        # Act
        desktop_image, min_cpu, max_cpu, min_ram, max_ram, desktop_configuration_id = service.get_desktop_configuration(
            config_id, current_user, session
        )

        # Assert
        assert desktop_image == "test-config-image:latest"
        assert min_cpu == 2
        assert max_cpu == 4
        assert min_ram == "4096Mi"
        assert max_ram == "8192Mi"
        assert desktop_configuration_id == 1

        # Verify mocks
        desktop_config_repo_mock.get_by_id.assert_called_once_with(config_id)

    def test_get_desktop_configuration_no_id(self, settings_mock):
        """Test getting desktop configuration without ID."""
        from services.connections import ConnectionsService

        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()
        config_id = None

        # Act
        desktop_image, min_cpu, max_cpu, min_ram, max_ram, desktop_configuration_id = service.get_desktop_configuration(
            config_id, current_user, session
        )

        # Assert
        assert desktop_image == "test-image:latest"  # From settings mock
        assert min_cpu == 1
        assert max_cpu == 4
        assert min_ram == "4096Mi"
        assert max_ram == "16384Mi"
        assert desktop_configuration_id is None

    def test_get_desktop_configuration_not_found(self, desktop_config_repo_mock):
        """Test getting desktop configuration that doesn't exist."""
        from services.connections import ConnectionsService

        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()
        config_id = 999  # Non-existent ID

        # Setup mock to return None
        desktop_config_repo_mock.get_by_id.return_value = None

        # Act & Assert
        with pytest.raises(NotFoundError) as excinfo:
            service.get_desktop_configuration(config_id, current_user, session)

        assert "Desktop configuration not found" in str(excinfo.value)

    def test_get_desktop_configuration_no_permission(self, desktop_config_repo_mock):
        """Test getting desktop configuration without permission."""
        from services.connections import ConnectionsService

        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user2"  # Different user
        current_user.is_admin = False
        session = MagicMock()
        config_id = 1

        # Act & Assert
        with pytest.raises(ForbiddenError) as excinfo:
            service.get_desktop_configuration(config_id, current_user, session)

        assert "You do not have permission to use this configuration" in str(excinfo.value)

    def test_provision_desktop_resources(self, rancher_client_mock):
        """Test provisioning desktop resources."""
        from services.connections import ConnectionsService

        # Arrange
        service = ConnectionsService()
        name = "test-desktop"
        vnc_password = "test-password"
        desktop_image = "test-image:latest"
        min_cpu = 1
        max_cpu = 4
        min_ram = "4096Mi"
        max_ram = "16384Mi"
        persistent_home = True
        external_pvc = "test-pvc"

        # Act
        status, client = service.provision_desktop_resources(
            name, vnc_password, desktop_image, min_cpu, max_cpu, min_ram, max_ram, persistent_home, external_pvc
        )

        # Assert
        assert status == "ready"  # Since check_vnc_ready returns True
        assert client == rancher_client_mock  # Should return the mocked client

        # Verify mocks
        rancher_client_mock.install.assert_called_once()
        rancher_client_mock.check_vnc_ready.assert_called_once_with(name)

    def test_scale_up_success(
        self,
        settings_mock,
        desktop_config_repo_mock,
        rancher_client_mock,
        connection_repo_mock,
        generate_unique_connection_name_mock,
        generate_random_string_mock,
    ):
        """Test scaling up a desktop successfully."""
        from services.connections import ConnectionsService

        # Arrange
        service = ConnectionsService()
        data = {"name": "test-desktop", "persistent_home": True, "desktop_configuration_id": 1}
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()

        # Act
        with patch.object(ConnectionsService, "validate_scale_up_input"), patch.object(
            ConnectionsService, "get_desktop_configuration"
        ) as mock_get_config, patch.object(
            ConnectionsService, "provision_desktop_resources"
        ) as mock_provision, patch.object(ConnectionsService, "save_connection_to_database") as mock_save:
            # Setup inner mocks
            mock_get_config.return_value = ("test-image:latest", 1, 4, "4096Mi", "16384Mi", 1)
            mock_provision.return_value = ("ready", rancher_client_mock)

            result = service.scale_up(data, current_user, session)

        # Assert
        assert result["name"] == "test-desktop"
        assert result["created_by"] == "user1"
        assert result["status"] == "ready"
        assert result["persistent_home"] is True
        assert result["desktop_configuration_id"] == 1

        # Verify mocks were called correctly
        generate_unique_connection_name_mock.assert_called_once()
        generate_random_string_mock.assert_called_once()

    def test_list_connections_as_admin(self, connection_repo_mock, guacamole_json_auth_mock, settings_mock):
        """Test listing connections as admin."""
        from services.connections import ConnectionsService

        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "admin"
        current_user.is_admin = True
        session = MagicMock()

        # Act
        result = service.list_connections(current_user, session=session)

        # Assert
        assert "connections" in result
        assert len(result["connections"]) == 2
        assert result["connections"][0]["name"] == "test-desktop"
        assert result["connections"][1]["name"] == "test-desktop-2"

        # Verify mocks
        connection_repo_mock.get_all_connections.assert_called_once()

    def test_list_connections_as_user(self, connection_repo_mock, guacamole_json_auth_mock, settings_mock):
        """Test listing connections as regular user."""
        from services.connections import ConnectionsService

        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()

        # Act
        result = service.list_connections(current_user, session=session)

        # Assert
        assert "connections" in result
        assert len(result["connections"]) == 1
        assert result["connections"][0]["name"] == "test-desktop"

        # Verify mocks
        connection_repo_mock.get_connections_by_creator.assert_called_once_with("user1")

    def test_get_connection_success(self, connection_repo_mock):
        """Test getting a connection successfully."""
        from services.connections import ConnectionsService

        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()
        connection_name = "test-desktop"

        # Act
        result = service.get_connection(connection_name, current_user, session)

        # Assert
        assert "connection" in result
        assert result["connection"]["name"] == "test-desktop"
        assert result["connection"]["created_by"] == "user1"

        # Verify mocks
        connection_repo_mock.get_by_name.assert_called_once_with(connection_name)

    def test_get_connection_not_found(self, connection_repo_mock):
        """Test getting a connection that doesn't exist."""
        from services.connections import ConnectionsService

        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()
        connection_name = "nonexistent-desktop"

        # Setup mock to return None
        connection_repo_mock.get_by_name.return_value = None

        # Act & Assert
        with pytest.raises(NotFoundError) as excinfo:
            service.get_connection(connection_name, current_user, session)

        assert "Connection not found" in str(excinfo.value)

    def test_get_connection_no_permission(self, connection_repo_mock):
        """Test getting a connection without permission."""
        from services.connections import ConnectionsService

        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user2"  # Different user
        current_user.is_admin = False
        session = MagicMock()
        connection_name = "test-desktop"

        # Setup connection owner
        connection = MagicMock()
        connection.name = "test-desktop"
        connection.created_by = "user1"  # Different from current_user
        connection_repo_mock.get_by_name.return_value = connection

        # Act & Assert
        with pytest.raises(ForbiddenError) as excinfo:
            service.get_connection(connection_name, current_user, session)

        assert "You do not have permission to access this connection" in str(excinfo.value)

    def test_direct_connect_success(
        self,
        connection_repo_mock,
        settings_mock,
        guacamole_json_auth_mock,
        guacamole_client_mock,
        decrypt_password_mock,
    ):
        """Test direct connect successfully."""
        from services.connections import ConnectionsService

        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()
        connection_id = 1

        # Act
        result = service.direct_connect(connection_id, current_user, session)

        # Assert
        assert "auth_url" in result
        assert "https://guacamole.example.com/#/?token=mock-jwt-token" == result["auth_url"]
        assert result["connection_id"] == 1
        assert result["connection_name"] == "test-desktop"

        # Verify mocks were called correctly
        connection_repo_mock.get_by_id.assert_called_once_with(connection_id)
        decrypt_password_mock.assert_called_once_with("encrypted_password")
        guacamole_client_mock.json_auth_login.assert_called_once()

    def test_direct_connect_not_found(self, connection_repo_mock):
        """Test direct connect with non-existent connection."""
        from services.connections import ConnectionsService

        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()
        connection_id = 999  # Non-existent ID

        # Setup mock to return None
        connection_repo_mock.get_by_id.return_value = None

        # Act & Assert
        with pytest.raises(NotFoundError) as excinfo:
            service.direct_connect(connection_id, current_user, session)

        assert "Connection not found" in str(excinfo.value)

    def test_scale_down_success(self, connection_repo_mock, rancher_client_mock):
        """Test scaling down a desktop successfully."""
        from services.connections import ConnectionsService

        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()
        connection_name = "test-desktop"

        # Act
        result = service.scale_down(connection_name, current_user, session)

        # Assert
        assert "message" in result
        assert "scaled down and preserved" in result["message"]

        # Verify mocks
        connection_repo_mock.get_by_name.assert_called_once_with(connection_name)
        rancher_client_mock.uninstall.assert_called_once_with(connection_name)
        rancher_client_mock.check_release_uninstalled.assert_called_once_with(connection_name)
        connection_repo_mock.update_connection.assert_called_once()
