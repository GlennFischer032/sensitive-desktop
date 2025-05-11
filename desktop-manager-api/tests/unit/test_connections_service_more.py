"""
Additional tests for connections service focusing on less covered methods.

This file tests the methods with lower coverage in the original test file:
- resume_connection
- permanent_delete
- attach_pvc_to_connection
- detach_pvc_from_connection
"""

import pytest
import sys
import os
from datetime import datetime
from unittest.mock import patch, MagicMock, call, ANY

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from services.connections import (
    APIError,
    BadRequestError,
    NotFoundError,
    ForbiddenError,
    ConnectionsService,
)


class TestConnectionsServiceExtra:
    """Additional tests for the ConnectionsService."""

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
            connection.hostname = "test-desktop.example.com"
            connection.port = "5900"
            connection.encrypted_password = "encrypted_password"
            connection.persistent_home = True
            connection.is_stopped = True  # For resume tests
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
            mock_instance.update_connection.return_value = connection

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

            # Configure mock methods
            mock_instance.get_by_name.return_value = pvc
            mock_instance.get_pvcs_for_user.return_value = [pvc]

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
            rancher_client.get_pvc.return_value = {"name": "test-desktop-home"}
            rancher_client.delete_pvc.return_value = None

            factory_mock.get_rancher_client.return_value = rancher_client
            yield rancher_client

    @pytest.fixture
    def generate_random_string_mock(self):
        """Mock generate_random_string."""
        with patch("services.connections.generate_random_string") as mock:
            mock.return_value = "random_password"
            yield mock

    # ======== resume_connection tests ========

    def test_resume_connection_success(
        self,
        connection_repo_mock,
        rancher_client_mock,
        desktop_config_repo_mock,
        settings_mock,
        generate_random_string_mock,
    ):
        """Test resuming a stopped connection successfully."""
        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()

        # Setup mock for desktop config
        with patch.object(service, "get_desktop_configuration") as mock_get_config:
            mock_get_config.return_value = (
                "test-image:latest",  # desktop_image
                2,  # min_cpu
                4,  # max_cpu
                "4096Mi",  # min_ram
                "8192Mi",  # max_ram
                1,  # desktop_configuration_id
            )

            # Act
            result = service.resume_connection("test-desktop", current_user, session)

        # Assert
        assert "message" in result
        assert "Connection test-desktop resumed successfully" in result["message"]
        assert "connection" in result
        assert result["connection"]["name"] == "test-desktop"
        assert result["connection"]["status"] == "ready"

        # Verify mock calls
        connection_repo_mock.get_by_name.assert_called_with("test-desktop")
        rancher_client_mock.install.assert_called_once()
        rancher_client_mock.check_vnc_ready.assert_called_once_with("test-desktop")
        connection_repo_mock.update_connection.assert_called_once_with(
            1,  # connection id
            {
                "is_stopped": False,
                "hostname": "test-desktop.example.com",
                "port": "5900",
                "vnc_password": "random_password",
            },
        )

    def test_resume_connection_not_found(self, connection_repo_mock):
        """Test resuming a non-existent connection."""
        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()

        # Setup mock to return None
        connection_repo_mock.get_by_name.return_value = None

        # Act & Assert
        with pytest.raises(NotFoundError) as excinfo:
            service.resume_connection("nonexistent-desktop", current_user, session)

        assert "Stopped connection nonexistent-desktop not found" in str(excinfo.value)

    def test_resume_connection_no_permission(self, connection_repo_mock):
        """Test resuming a connection without permission."""
        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user2"  # Different user
        current_user.is_admin = False
        session = MagicMock()

        # Mock connection with different owner
        connection = MagicMock()
        connection.id = 1
        connection.name = "test-desktop"
        connection.created_by = "user1"  # Different from current user
        connection.is_stopped = True
        connection_repo_mock.get_by_name.return_value = connection

        # Act & Assert
        with pytest.raises(ForbiddenError) as excinfo:
            service.resume_connection("test-desktop", current_user, session)

        assert "You do not have permission to resume this connection" in str(excinfo.value)

    def test_resume_connection_vnc_not_ready(
        self,
        connection_repo_mock,
        rancher_client_mock,
        desktop_config_repo_mock,
        settings_mock,
        generate_random_string_mock,
    ):
        """Test resuming a connection when VNC is not ready."""
        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()

        # Setup mocks
        rancher_client_mock.check_vnc_ready.return_value = False  # VNC not ready

        # Setup mock for desktop config
        with patch.object(service, "get_desktop_configuration") as mock_get_config:
            mock_get_config.return_value = (
                "test-image:latest",
                2,
                4,
                "4096Mi",
                "8192Mi",
                1,
            )

            # Act
            result = service.resume_connection("test-desktop", current_user, session)

        # Assert
        assert "connection" in result
        assert result["connection"]["status"] == "provisioning"  # Should be provisioning, not ready

        # Verify mock calls
        rancher_client_mock.check_vnc_ready.assert_called_once_with("test-desktop")

    # ======== permanent_delete tests ========

    def test_permanent_delete_success(self, connection_repo_mock, rancher_client_mock):
        """Test permanently deleting a stopped connection."""
        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()

        # Act
        result = service.permanent_delete("test-desktop", current_user, session)

        # Assert
        assert "message" in result
        assert "Connection test-desktop permanently deleted" in result["message"]
        assert "and PVC test-desktop-home removed" in result["message"]

        # Verify mock calls
        connection_repo_mock.get_by_name.assert_called_once_with("test-desktop")
        rancher_client_mock.get_pvc.assert_called_once_with(name="test-desktop-home")
        rancher_client_mock.delete_pvc.assert_called_once_with(name="test-desktop-home")
        connection_repo_mock.delete_connection.assert_called_once_with(1)

    def test_permanent_delete_not_found(self, connection_repo_mock):
        """Test permanently deleting a non-existent connection."""
        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()

        # Setup mock to return None
        connection_repo_mock.get_by_name.return_value = None

        # Act & Assert
        with pytest.raises(NotFoundError) as excinfo:
            service.permanent_delete("nonexistent-desktop", current_user, session)

        assert "Connection nonexistent-desktop not found" in str(excinfo.value)

    def test_permanent_delete_not_stopped(self, connection_repo_mock):
        """Test permanently deleting a connection that's not stopped."""
        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()

        # Mock active connection
        connection = MagicMock()
        connection.id = 1
        connection.name = "test-desktop"
        connection.created_by = "user1"
        connection.is_stopped = False  # Not stopped
        connection_repo_mock.get_by_name.return_value = connection

        # Act & Assert
        with pytest.raises(BadRequestError) as excinfo:
            service.permanent_delete("test-desktop", current_user, session)

        assert "Connection test-desktop must be stopped first" in str(excinfo.value)

    def test_permanent_delete_no_permission(self, connection_repo_mock):
        """Test permanently deleting a connection without permission."""
        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user2"  # Different user
        current_user.is_admin = False
        session = MagicMock()

        # Mock connection with different owner
        connection = MagicMock()
        connection.id = 1
        connection.name = "test-desktop"
        connection.created_by = "user1"  # Different from current user
        connection.is_stopped = True
        connection_repo_mock.get_by_name.return_value = connection

        # Act & Assert
        with pytest.raises(ForbiddenError) as excinfo:
            service.permanent_delete("test-desktop", current_user, session)

        assert "You do not have permission to delete this connection" in str(excinfo.value)

    def test_permanent_delete_pvc_error(self, connection_repo_mock, rancher_client_mock):
        """Test permanently deleting a connection when PVC deletion fails."""
        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()

        # Setup mocks for PVC error
        rancher_client_mock.get_pvc.side_effect = Exception("PVC not found")

        # Act
        result = service.permanent_delete("test-desktop", current_user, session)

        # Assert
        assert "message" in result
        assert "Connection test-desktop permanently deleted" in result["message"]
        assert "but failed to delete PVC test-desktop-home" in result["message"]

        # Verify mock calls
        connection_repo_mock.get_by_name.assert_called_once_with("test-desktop")
        rancher_client_mock.get_pvc.assert_called_once_with(name="test-desktop-home")
        rancher_client_mock.delete_pvc.assert_not_called()  # Should not be called when get_pvc fails
        connection_repo_mock.delete_connection.assert_called_once_with(1)

    def test_permanent_delete_admin_permission(self, connection_repo_mock, rancher_client_mock):
        """Test permanently deleting a connection as admin."""
        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "admin"
        current_user.is_admin = True
        session = MagicMock()

        # Mock connection owned by different user
        connection = MagicMock()
        connection.id = 1
        connection.name = "test-desktop"
        connection.created_by = "user1"  # Different from admin
        connection.is_stopped = True
        connection_repo_mock.get_by_name.return_value = connection

        # Act
        result = service.permanent_delete("test-desktop", current_user, session)

        # Assert
        assert "message" in result
        assert "Connection test-desktop permanently deleted" in result["message"]

        # Verify mock calls
        connection_repo_mock.delete_connection.assert_called_once_with(1)

    # ======== attach_pvc_to_connection tests ========

    def test_attach_pvc_to_connection_success(
        self,
        connection_repo_mock,
        storage_pvc_repo_mock,
        rancher_client_mock,
    ):
        """Test attaching a PVC to a connection successfully."""
        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()

        # Mock the scale_down and resume_connection methods
        with patch.object(service, "scale_down") as mock_scale_down, patch.object(
            service, "resume_connection"
        ) as mock_resume:
            # Act
            service.attach_pvc_to_connection(1, 1, current_user, session)

            # Assert
            connection_repo_mock.attach_pvc_to_connection.assert_called_once_with(1, 1)

            # Since connection is stopped, no need to restart
            mock_scale_down.assert_not_called()
            mock_resume.assert_not_called()

    def test_attach_pvc_to_connection_active(
        self,
        connection_repo_mock,
        storage_pvc_repo_mock,
    ):
        """Test attaching a PVC to an active connection."""
        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()

        # Mock an active connection
        connection = MagicMock()
        connection.id = 1
        connection.name = "test-desktop"
        connection.created_by = "user1"
        connection.is_stopped = False  # Active connection
        connection_repo_mock.get_by_id.return_value = connection

        # Mock the scale_down and resume_connection methods
        with patch.object(service, "scale_down") as mock_scale_down, patch.object(
            service, "resume_connection"
        ) as mock_resume:
            # Act
            service.attach_pvc_to_connection(1, 1, current_user, session)

            # Assert
            connection_repo_mock.attach_pvc_to_connection.assert_called_once_with(1, 1)

            # Should restart the connection
            mock_scale_down.assert_called_once_with("test-desktop", current_user, session)
            mock_resume.assert_called_once_with("test-desktop", current_user, session)

    def test_attach_pvc_to_connection_no_permission(
        self,
        connection_repo_mock,
        storage_pvc_repo_mock,
    ):
        """Test attaching a PVC to a connection without permission."""
        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user2"  # Different user
        current_user.is_admin = False
        session = MagicMock()

        # Setup mock to return empty list (no access to PVC)
        storage_pvc_repo_mock.get_pvcs_for_user.return_value = []

        # Act & Assert
        with pytest.raises(ForbiddenError) as excinfo:
            service.attach_pvc_to_connection(1, 1, current_user, session)

        assert "You do not have permission to attach this PVC" in str(excinfo.value)

    # ======== detach_pvc_from_connection tests ========

    def test_detach_pvc_from_connection_success(
        self,
        connection_repo_mock,
    ):
        """Test detaching a PVC from a connection successfully."""
        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()

        # Mock the scale_down and resume_connection methods
        with patch.object(service, "scale_down") as mock_scale_down, patch.object(
            service, "resume_connection"
        ) as mock_resume:
            # Act
            service.detach_pvc_from_connection(1, current_user, session)

            # Assert
            connection_repo_mock.detach_pvc_from_connection.assert_called_once_with(1)

            # Since connection is stopped, no need to restart
            mock_scale_down.assert_not_called()
            mock_resume.assert_not_called()

    def test_detach_pvc_from_connection_active(
        self,
        connection_repo_mock,
    ):
        """Test detaching a PVC from an active connection."""
        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()

        # Mock an active connection
        connection = MagicMock()
        connection.id = 1
        connection.name = "test-desktop"
        connection.created_by = "user1"
        connection.is_stopped = False  # Active connection
        connection_repo_mock.get_by_id.return_value = connection

        # Mock the scale_down and resume_connection methods
        with patch.object(service, "scale_down") as mock_scale_down, patch.object(
            service, "resume_connection"
        ) as mock_resume:
            # Act
            service.detach_pvc_from_connection(1, current_user, session)

            # Assert
            connection_repo_mock.detach_pvc_from_connection.assert_called_once_with(1)

            # Should restart the connection
            mock_scale_down.assert_called_once_with("test-desktop", current_user, session)
            mock_resume.assert_called_once_with("test-desktop", current_user, session)

    # ======== Error handling tests ========

    def test_resume_connection_rancher_failure(
        self,
        connection_repo_mock,
        rancher_client_mock,
        desktop_config_repo_mock,
    ):
        """Test resuming a connection when Rancher install fails."""
        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "user1"
        current_user.is_admin = False
        session = MagicMock()

        # Setup mocks
        rancher_client_mock.install.side_effect = Exception("Rancher install failed")

        # Setup mock for desktop config
        with patch.object(service, "get_desktop_configuration") as mock_get_config:
            mock_get_config.return_value = (
                "test-image:latest",
                2,
                4,
                "4096Mi",
                "8192Mi",
                1,
            )

            # Act & Assert
            with pytest.raises(APIError) as excinfo:
                service.resume_connection("test-desktop", current_user, session)

            assert "Rancher install failed" in str(excinfo.value)

    def test_attach_pvc_admin_bypass(
        self,
        connection_repo_mock,
        storage_pvc_repo_mock,
    ):
        """Test that admins can attach any PVC regardless of ownership."""
        # Arrange
        service = ConnectionsService()
        current_user = MagicMock()
        current_user.username = "admin"
        current_user.is_admin = True
        session = MagicMock()

        # Setup mock to return empty list (no direct access to PVC)
        storage_pvc_repo_mock.get_pvcs_for_user.return_value = []

        # Act - should not raise an exception for admin
        service.attach_pvc_to_connection(1, 1, current_user, session)

        # Assert
        connection_repo_mock.attach_pvc_to_connection.assert_called_once_with(1, 1)
