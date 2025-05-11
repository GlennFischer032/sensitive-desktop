"""
Tests for the Storage PVC service.
"""

import pytest
import sys
import os
from unittest.mock import patch, MagicMock
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from services.storage_pvc import StoragePVCService
from services.connections import APIError, BadRequestError, NotFoundError


class MockPVC:
    """Mock PVC object to avoid MagicMock issues."""

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class TestStoragePVCService:
    """Test class for StoragePVCService."""

    @pytest.fixture
    def service(self):
        """Create a StoragePVCService instance."""
        return StoragePVCService()

    @pytest.fixture
    def storage_repo_mock(self):
        """Mock StoragePVCRepository."""
        with patch("services.storage_pvc.StoragePVCRepository") as mock:
            mock_instance = MagicMock()

            # Create a proper mock PVC without setting __dict__
            pvc = MockPVC(
                id=1,
                name="test-pvc",
                size="10Gi",
                storage_size="10Gi",
                is_public=True,
                description="Test description",
                created_at=datetime.utcnow(),
                created_by="test-user",
                namespace="default",
                status="Pending",
                last_updated=datetime.utcnow(),
            )

            # Override is_pvc_in_use for delete tests - set to False by default
            mock_instance.is_pvc_in_use.return_value = False

            # Mock for create_pvc
            mock_instance.create_storage_pvc.return_value = pvc

            # Mock for get_by_id - ensure it returns our MockPVC
            mock_instance.get_by_id.return_value = pvc

            # Mock for get_by_name - initially returns None (PVC not found)
            mock_instance.get_by_name.return_value = None

            # Mock for get_all_pvcs
            pvc2 = MockPVC(
                id=2,
                name="test-pvc-2",
                size="20Gi",
                storage_size="20Gi",
                is_public=False,
                description="Test description 2",
                created_at=datetime.utcnow(),
                created_by="another-user",
                namespace="default",
                status="Pending",
                last_updated=datetime.utcnow(),
            )

            # Setup collection returns
            mock_instance.get_pvcs_for_admin.return_value = [pvc, pvc2]
            mock_instance.get_pvcs_for_user.return_value = [pvc]

            # Mock for update_pvc
            mock_instance.update_storage_pvc.return_value = pvc

            # Mock for delete_pvc
            mock_instance.delete_storage_pvc.return_value = None

            # Mock for get_pvc_users
            mock_instance.get_pvc_users.return_value = ["user1", "user2"]

            mock.return_value = mock_instance
            yield mock_instance

    @pytest.fixture
    def rancher_client_mock(self):
        """Mock RancherClient."""
        with patch("services.storage_pvc.client_factory") as factory_mock:
            client = MagicMock()
            factory_mock.get_rancher_client.return_value = client

            # Setup the client methods
            client.create_pvc.return_value = {"name": "test-pvc", "namespace": "default"}
            client.get_pvc.return_value = {"status": {"phase": "Bound"}}

            yield client

    @pytest.fixture
    def mock_pydantic_validation(self):
        """Mock StoragePVCModel validation."""
        with patch("services.storage_pvc.StoragePVCModel") as model_mock:
            model_instance = MagicMock()
            model_instance.model_dump.return_value = {
                "id": 1,
                "name": "test-pvc",
                "namespace": "default",
                "size": "10Gi",
                "is_public": True,
                "description": "Test description",
                "created_at": datetime.utcnow().isoformat(),
                "created_by": "test-user",
                "status": "Bound",
                "last_updated": datetime.utcnow().isoformat(),
            }
            model_mock.model_validate.return_value = model_instance
            yield model_mock

    def test_create_storage_pvc(self, service, storage_repo_mock, rancher_client_mock, mock_pydantic_validation):
        """Test creating a storage PVC."""
        # Arrange
        data = {"name": "test-pvc", "size": "10Gi", "is_public": True, "description": "Test description"}
        current_user = MagicMock()
        current_user.username = "test-user"
        session = MagicMock()

        # Make sure get_by_name returns None (PVC doesn't exist yet)
        storage_repo_mock.get_by_name.return_value = None

        # Act
        result = service.create_storage_pvc(data, current_user, session)

        # Assert
        assert "message" in result
        assert "PVC created successfully" in result["message"]
        assert "pvc" in result

        # Verify mocks
        storage_repo_mock.create_storage_pvc.assert_called_once()
        rancher_client_mock.create_pvc.assert_called_once()

    def test_create_storage_pvc_missing_data(self, service):
        """Test creating a storage PVC with missing data."""
        # Arrange
        data = None
        current_user = MagicMock()
        current_user.username = "test-user"
        session = MagicMock()

        # Act & Assert
        with pytest.raises(BadRequestError) as excinfo:
            service.create_storage_pvc(data, current_user, session)

        assert "No input data provided" in str(excinfo.value)

    def test_create_storage_pvc_missing_name(self, service):
        """Test creating a storage PVC with missing name."""
        # Arrange
        data = {"size": "10Gi", "is_public": True}
        current_user = MagicMock()
        current_user.username = "test-user"
        session = MagicMock()

        # Act & Assert
        with pytest.raises(BadRequestError) as excinfo:
            service.create_storage_pvc(data, current_user, session)

        assert "Missing required field: name" in str(excinfo.value)

    def test_create_storage_pvc_already_exists(self, service, storage_repo_mock):
        """Test creating a storage PVC that already exists."""
        # Arrange
        data = {"name": "test-pvc", "size": "10Gi", "is_public": True, "description": "Test description"}
        current_user = MagicMock()
        current_user.username = "test-user"
        session = MagicMock()

        # Mock PVC already exists
        existing_pvc = MockPVC(name="test-pvc")
        storage_repo_mock.get_by_name.return_value = existing_pvc

        # Act & Assert
        with pytest.raises(BadRequestError) as excinfo:
            service.create_storage_pvc(data, current_user, session)

        assert "already exists" in str(excinfo.value)

    def test_list_storage_pvcs_as_admin(self, service, storage_repo_mock, mock_pydantic_validation):
        """Test listing storage PVCs as admin."""
        # Arrange
        current_user = MagicMock()
        current_user.username = "admin-user"
        current_user.is_admin = True
        session = MagicMock()

        # Act
        result = service.list_storage_pvcs(current_user, session)

        # Assert
        assert "pvcs" in result
        assert len(result["pvcs"]) == 2

        # Verify mocks
        storage_repo_mock.get_pvcs_for_admin.assert_called_once()

    def test_list_storage_pvcs_as_user(self, service, storage_repo_mock, mock_pydantic_validation):
        """Test listing storage PVCs as a regular user."""
        # Arrange
        current_user = MagicMock()
        current_user.username = "test-user"
        current_user.is_admin = False
        session = MagicMock()

        # Act
        result = service.list_storage_pvcs(current_user, session)

        # Assert
        assert "pvcs" in result
        assert len(result["pvcs"]) == 1

        # Verify mocks
        storage_repo_mock.get_pvcs_for_user.assert_called_once_with("test-user")

    def test_get_storage_pvc_by_id(self, service, storage_repo_mock, rancher_client_mock, mock_pydantic_validation):
        """Test getting a storage PVC by ID."""
        # Arrange
        pvc_id = 1
        session = MagicMock()

        # Ensure get_by_id is called with correct ID
        storage_repo_mock.get_by_id.return_value = MockPVC(
            id=1, name="test-pvc", size="10Gi", namespace="default", status="Pending"
        )

        # Act
        result = service.get_storage_pvc_by_id(pvc_id, session)

        # Assert
        assert "pvc" in result

        # Verify mocks
        storage_repo_mock.get_by_id.assert_called_once_with(pvc_id)
        rancher_client_mock.get_pvc.assert_called_once()

    def test_get_storage_pvc_by_id_not_found(self, service, storage_repo_mock):
        """Test getting a non-existent storage PVC by ID."""
        # Arrange
        pvc_id = 999
        session = MagicMock()

        # Mock PVC not found
        storage_repo_mock.get_by_id.return_value = None

        # Act & Assert
        with pytest.raises(NotFoundError) as excinfo:
            service.get_storage_pvc_by_id(pvc_id, session)

        assert f"PVC with ID {pvc_id} not found" in str(excinfo.value)

    def test_delete_storage_pvc(self, service, storage_repo_mock, rancher_client_mock):
        """Test deleting a storage PVC."""
        # Arrange
        pvc_id = 1
        session = MagicMock()

        # Explicitly set is_pvc_in_use to False (already set in fixture)

        # Act
        result = service.delete_storage_pvc(pvc_id, session)

        # Assert
        assert "message" in result
        assert "deleted successfully" in result["message"]

        # Verify mocks
        storage_repo_mock.get_by_id.assert_called_once_with(pvc_id)
        rancher_client_mock.delete_pvc.assert_called_once()
        storage_repo_mock.delete_storage_pvc.assert_called_once_with(1)

    def test_delete_storage_pvc_not_found(self, service, storage_repo_mock):
        """Test deleting a non-existent storage PVC."""
        # Arrange
        pvc_id = 999
        session = MagicMock()

        # Mock PVC not found
        storage_repo_mock.get_by_id.return_value = None

        # Act & Assert
        with pytest.raises(NotFoundError) as excinfo:
            service.delete_storage_pvc(pvc_id, session)

        assert f"PVC with ID {pvc_id} not found" in str(excinfo.value)

    def test_delete_storage_pvc_in_use(self, service, storage_repo_mock):
        """Test deleting a storage PVC that is in use."""
        # Arrange
        pvc_id = 1
        session = MagicMock()

        # Mock is_pvc_in_use to return True for this test
        storage_repo_mock.is_pvc_in_use.return_value = True

        # Act & Assert
        with pytest.raises(BadRequestError) as excinfo:
            service.delete_storage_pvc(pvc_id, session)

        assert "Cannot delete PVC that is in use" in str(excinfo.value)

    def test_get_pvc_access(self, service, storage_repo_mock):
        """Test getting PVC access."""
        # Arrange
        pvc_id = 1
        session = MagicMock()

        # Act
        result = service.get_pvc_access(pvc_id, session)

        # Assert
        assert "users" in result
        assert len(result["users"]) == 2

        # Verify mocks
        storage_repo_mock.get_pvc_users.assert_called_once_with(pvc_id)

    def test_update_pvc_access(self, service, storage_repo_mock):
        """Test updating PVC access."""
        # Arrange
        pvc_id = 1
        data = {"is_public": True, "allowed_users": ["user1", "user2"]}
        session = MagicMock()

        # Act
        result = service.update_pvc_access(pvc_id, data, session)

        # Assert
        assert "message" in result
        assert "PVC access updated successfully" in result["message"]

        # Verify mocks
        storage_repo_mock.get_by_id.assert_called_once_with(pvc_id)
        storage_repo_mock.update_storage_pvc.assert_called_once()
        storage_repo_mock.clear_pvc_access.assert_called_once_with(pvc_id)

    def test_update_pvc_access_missing_data(self, service):
        """Test updating PVC access with missing data."""
        # Arrange
        pvc_id = 1
        data = None
        session = MagicMock()

        # Act & Assert
        with pytest.raises(BadRequestError) as excinfo:
            service.update_pvc_access(pvc_id, data, session)

        assert "No input data provided" in str(excinfo.value)

    def test_update_pvc_access_not_found(self, service, storage_repo_mock):
        """Test updating access for a non-existent PVC."""
        # Arrange
        pvc_id = 999
        data = {"is_public": True, "allowed_users": ["user1", "user2"]}
        session = MagicMock()

        # Mock PVC not found
        storage_repo_mock.get_by_id.return_value = None

        # Act & Assert
        with pytest.raises(NotFoundError) as excinfo:
            service.update_pvc_access(pvc_id, data, session)

        assert f"PVC with ID {pvc_id} not found" in str(excinfo.value)

    def test_get_pvc_connections(self, service, storage_repo_mock):
        """Test getting connections for a PVC."""
        # Arrange
        pvc_id = 1
        session = MagicMock()

        # Mock ConnectionRepository
        with patch("services.storage_pvc.ConnectionRepository") as conn_repo_mock:
            conn_repo_instance = MagicMock()
            conn_repo_mock.return_value = conn_repo_instance

            # Mock connections
            connection1 = MockPVC(
                id=1, name="conn1", created_by="test-user", created_at=datetime.utcnow(), is_stopped=False
            )

            connection2 = MockPVC(
                id=2, name="conn2", created_by="test-user", created_at=datetime.utcnow(), is_stopped=True
            )

            conn_repo_instance.get_connections_for_pvc.return_value = [connection1, connection2]

            # Act
            result = service.get_pvc_connections(pvc_id, session)

            # Assert
            assert "connections" in result
            assert len(result["connections"]) == 2

            # Verify mocks
            conn_repo_instance.get_connections_for_pvc.assert_called_once_with(pvc_id)
