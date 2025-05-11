"""
Unit tests for the StoragePVCRepository class.
"""

import pytest
import sys
import os
from datetime import datetime
from unittest.mock import MagicMock, patch

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from database.repositories.storage_pvc import StoragePVCRepository
from database.models.storage_pvc import StoragePVC, StoragePVCAccess, ConnectionPVCMap
from database.models.user import User


class TestStoragePVCRepository:
    """Tests for the StoragePVCRepository class."""

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
        """Create a StoragePVCRepository instance with a mock session."""
        return StoragePVCRepository(mock_session)

    @pytest.fixture
    def sample_pvc(self):
        """Create a sample PVC for testing."""
        pvc = MagicMock(spec=StoragePVC)
        pvc.id = 1
        pvc.name = "test-pvc"
        pvc.namespace = "default"
        pvc.size = "10Gi"
        pvc.created_by = "admin"
        pvc.status = "Bound"
        pvc.is_public = False
        pvc.created_at = datetime.now()
        pvc.last_updated = datetime.now()
        return pvc

    @pytest.fixture
    def sample_user(self):
        """Create a sample user for testing."""
        user = MagicMock(spec=User)
        user.username = "testuser"
        user.is_admin = False
        return user

    @pytest.fixture
    def sample_admin_user(self):
        """Create a sample admin user for testing."""
        user = MagicMock(spec=User)
        user.username = "admin"
        user.is_admin = True
        return user

    def test_get_by_name(self, repository, mock_session, sample_pvc):
        """
        GIVEN a repository and a PVC name
        WHEN get_by_name is called
        THEN it should query the database with the correct filter
        """
        # Set up the mock to return the sample PVC
        mock_session.query.return_value.filter.return_value.first.return_value = sample_pvc

        # Call the method
        result = repository.get_by_name("test-pvc")

        # Verify the result and interactions
        assert result == sample_pvc
        assert mock_session.query.called
        mock_session.query.return_value.filter.assert_called_once()
        mock_session.query.return_value.filter.return_value.first.assert_called_once()

    def test_get_by_id(self, repository, mock_session, sample_pvc):
        """
        GIVEN a repository and a PVC ID
        WHEN get_by_id is called
        THEN it should query the database with the correct filter
        """
        # Set up the mock to return the sample PVC
        mock_session.query.return_value.filter.return_value.first.return_value = sample_pvc

        # Call the method
        result = repository.get_by_id(1)

        # Verify the result and interactions
        assert result == sample_pvc
        assert mock_session.query.called
        mock_session.query.return_value.filter.assert_called_once()
        mock_session.query.return_value.filter.return_value.first.assert_called_once()

    def test_create_storage_pvc(self, repository, mock_session):
        """
        GIVEN a repository and PVC data
        WHEN create_storage_pvc is called
        THEN it should create a new PVC with correct attributes
        """
        # Set up the mock for the create method
        with patch.object(repository, "create") as mock_create:
            mock_create.return_value = MagicMock(spec=StoragePVC)

            # Prepare test data
            pvc_data = {
                "name": "test-pvc",
                "namespace": "default",
                "size": "10Gi",
                "created_by": "admin",
                "status": "Bound",
                "is_public": True,
            }

            # Call the method
            result = repository.create_storage_pvc(pvc_data)

            # Verify that create was called with a StoragePVC object
            mock_create.assert_called_once()
            created_pvc = mock_create.call_args[0][0]
            assert isinstance(created_pvc, StoragePVC)
            assert created_pvc.name == "test-pvc"
            assert created_pvc.namespace == "default"
            assert created_pvc.size == "10Gi"
            assert created_pvc.created_by == "admin"
            assert created_pvc.status == "Bound"
            assert created_pvc.is_public is True

    def test_create_storage_pvc_with_minimal_data(self, repository, mock_session):
        """
        GIVEN a repository and minimal PVC data
        WHEN create_storage_pvc is called
        THEN it should create a new PVC with default values
        """
        # Set up the mock for the create method
        with patch.object(repository, "create") as mock_create:
            mock_create.return_value = MagicMock(spec=StoragePVC)

            # Prepare minimal test data
            pvc_data = {
                "name": "test-pvc",
                "namespace": "default",
                "size": "10Gi",
                "created_by": "admin",
            }

            # Call the method
            result = repository.create_storage_pvc(pvc_data)

            # Verify that create was called with a StoragePVC object
            mock_create.assert_called_once()
            created_pvc = mock_create.call_args[0][0]
            assert created_pvc.name == "test-pvc"
            assert created_pvc.namespace == "default"
            assert created_pvc.size == "10Gi"
            assert created_pvc.created_by == "admin"
            assert created_pvc.status == "Pending"  # Default value
            assert created_pvc.is_public is False  # Default value

    def test_update_storage_pvc(self, repository, mock_session, sample_pvc):
        """
        GIVEN a repository and PVC data
        WHEN update_storage_pvc is called
        THEN it should update the PVC with the new values
        """
        # Set up the mock to return the sample PVC when get_by_id is called
        with patch.object(repository, "get_by_id", return_value=sample_pvc):
            # Set up the mock for the update method
            with patch.object(repository, "update") as mock_update:
                # Prepare test data
                update_data = {
                    "status": "Available",
                    "is_public": True,
                }

                # Call the method
                result = repository.update_storage_pvc(1, update_data)

                # Verify the result and interactions
                assert result == sample_pvc
                repository.get_by_id.assert_called_once_with(1)
                mock_update.assert_called_once_with(sample_pvc)

                # Verify that the PVC was updated
                assert sample_pvc.status == "Available"
                assert sample_pvc.is_public is True

    def test_update_storage_pvc_not_found(self, repository, mock_session):
        """
        GIVEN a repository and a non-existent PVC ID
        WHEN update_storage_pvc is called
        THEN it should return None
        """
        # Set up the mock to return None when get_by_id is called
        with patch.object(repository, "get_by_id", return_value=None):
            # Prepare test data
            update_data = {
                "status": "Available",
            }

            # Call the method
            result = repository.update_storage_pvc(999, update_data)

            # Verify the result and interactions
            assert result is None
            repository.get_by_id.assert_called_once_with(999)

    def test_delete_storage_pvc(self, repository, mock_session, sample_pvc):
        """
        GIVEN a repository and a PVC ID
        WHEN delete_storage_pvc is called
        THEN it should delete the PVC
        """
        # Set up the mock to return the sample PVC when get_by_id is called
        with patch.object(repository, "get_by_id", return_value=sample_pvc):
            # Call the method
            result = repository.delete_storage_pvc(1)

            # Verify the result and interactions
            assert result is True
            repository.get_by_id.assert_called_once_with(1)
            mock_session.delete.assert_called_once_with(sample_pvc)
            mock_session.commit.assert_called_once()

    def test_delete_storage_pvc_not_found(self, repository, mock_session):
        """
        GIVEN a repository and a non-existent PVC ID
        WHEN delete_storage_pvc is called
        THEN it should return False
        """
        # Set up the mock to return None when get_by_id is called
        with patch.object(repository, "get_by_id", return_value=None):
            # Call the method
            result = repository.delete_storage_pvc(999)

            # Verify the result and interactions
            assert result is False
            repository.get_by_id.assert_called_once_with(999)
            mock_session.delete.assert_not_called()
            mock_session.commit.assert_not_called()

    def test_get_pvcs_for_admin(self, repository, mock_session, sample_pvc):
        """
        GIVEN a repository
        WHEN get_pvcs_for_admin is called
        THEN it should return all PVCs
        """
        # Set up the mock to return a list of PVCs
        mock_session.query.return_value.order_by.return_value.all.return_value = [sample_pvc]

        # Call the method
        result = repository.get_pvcs_for_admin()

        # Verify the result and interactions
        assert result == [sample_pvc]
        assert mock_session.query.called
        mock_session.query.return_value.order_by.assert_called_once()
        mock_session.query.return_value.order_by.return_value.all.assert_called_once()

    def test_get_pvcs_for_user(self, repository, mock_session, sample_pvc):
        """
        GIVEN a repository and a username
        WHEN get_pvcs_for_user is called
        THEN it should query for PVCs accessible to the user
        """
        # Set up the mock to return a list of PVCs
        mock_session.query.return_value.filter.return_value.order_by.return_value.all.return_value = [sample_pvc]

        # Call the method
        result = repository.get_pvcs_for_user("testuser")

        # Verify the result and interactions
        assert result == [sample_pvc]
        # We don't check exactly what is passed to query() since it's a SQLAlchemy class
        assert mock_session.query.called
        assert mock_session.query.return_value.filter.called
        assert mock_session.query.return_value.filter.return_value.order_by.called
        assert mock_session.query.return_value.filter.return_value.order_by.return_value.all.called

    def test_user_has_access_to_pvc_user_not_found(self, repository, mock_session):
        """
        GIVEN a repository, PVC ID, and username for a non-existent user
        WHEN user_has_access_to_pvc is called
        THEN it should return False
        """
        # Set up the mock to return None for user query
        mock_session.query.return_value.filter.return_value.first.return_value = None

        # Call the method
        result = repository.user_has_access_to_pvc(1, "nonexistent")

        # Verify the result and interactions
        assert result is False
        assert mock_session.query.called
        mock_session.query.return_value.filter.assert_called_once()
        mock_session.query.return_value.filter.return_value.first.assert_called_once()

    def test_user_has_access_to_pvc_pvc_not_found(self, repository, mock_session, sample_user):
        """
        GIVEN a repository, non-existent PVC ID, and valid username
        WHEN user_has_access_to_pvc is called
        THEN it should return False
        """
        # Set up the mock to return user for first query, but None for PVC query
        mock_session.query.return_value.filter.return_value.first.side_effect = [sample_user, None]

        # Mock the get_by_id method to return None
        with patch.object(repository, "get_by_id", return_value=None):
            # Call the method
            result = repository.user_has_access_to_pvc(999, "testuser")

            # Verify the result and interactions
            assert result is False
            assert mock_session.query.called
            repository.get_by_id.assert_called_once_with(999)

    def test_user_has_access_to_pvc_direct_access(self, repository, mock_session, sample_user, sample_pvc):
        """
        GIVEN a repository, PVC ID, and username with direct access
        WHEN user_has_access_to_pvc is called
        THEN it should return True
        """
        # Set up the mock to return user
        mock_session.query.return_value.filter.return_value.first.return_value = sample_user

        # Configure the sample PVC users attribute to include the sample user
        sample_pvc.users = [sample_user]
        sample_pvc.is_public = False

        # Mock the get_by_id method to return the sample PVC
        with patch.object(repository, "get_by_id", return_value=sample_pvc):
            # Call the method
            result = repository.user_has_access_to_pvc(1, "testuser")

            # Verify the result and interactions
            assert result is True
            assert mock_session.query.called
            repository.get_by_id.assert_called_once_with(1)

    def test_user_has_access_to_pvc_public_pvc(self, repository, mock_session, sample_user, sample_pvc):
        """
        GIVEN a repository, public PVC ID, and username
        WHEN user_has_access_to_pvc is called
        THEN it should return True
        """
        # Set up the mock to return user
        mock_session.query.return_value.filter.return_value.first.return_value = sample_user

        # Configure the sample PVC to be public
        sample_pvc.users = []  # No direct access
        sample_pvc.is_public = True

        # Mock the get_by_id method to return the sample PVC
        with patch.object(repository, "get_by_id", return_value=sample_pvc):
            # Call the method
            result = repository.user_has_access_to_pvc(1, "testuser")

            # Verify the result and interactions
            assert result is True
            assert mock_session.query.called
            repository.get_by_id.assert_called_once_with(1)

    def test_user_has_access_to_pvc_admin_user(self, repository, mock_session, sample_admin_user, sample_pvc):
        """
        GIVEN a repository, PVC ID, and admin username
        WHEN user_has_access_to_pvc is called
        THEN it should return True
        """
        # Set up the mock to return admin user
        mock_session.query.return_value.filter.return_value.first.return_value = sample_admin_user

        # Configure the sample PVC to be private and no direct access
        sample_pvc.users = []  # No direct access
        sample_pvc.is_public = False

        # Mock the get_by_id method to return the sample PVC
        with patch.object(repository, "get_by_id", return_value=sample_pvc):
            # Call the method
            result = repository.user_has_access_to_pvc(1, "admin")

            # Verify the result and interactions
            assert result is True
            assert mock_session.query.called
            repository.get_by_id.assert_called_once_with(1)

    def test_user_has_no_access_to_pvc(self, repository, mock_session, sample_user, sample_pvc):
        """
        GIVEN a repository, private PVC ID, and username without access
        WHEN user_has_access_to_pvc is called
        THEN it should return False
        """
        # Set up the mock to return user
        mock_session.query.return_value.filter.return_value.first.return_value = sample_user

        # Configure the sample PVC to be private and no direct access
        sample_pvc.users = []  # No direct access
        sample_pvc.is_public = False

        # Mock the get_by_id method to return the sample PVC
        with patch.object(repository, "get_by_id", return_value=sample_pvc):
            # Call the method
            result = repository.user_has_access_to_pvc(1, "testuser")

            # Verify the result and interactions
            assert result is False
            assert mock_session.query.called
            repository.get_by_id.assert_called_once_with(1)

    def test_create_pvc_access(self, repository, mock_session):
        """
        GIVEN a repository, PVC ID, and username
        WHEN create_pvc_access is called
        THEN it should create a new access entry
        """
        # Call the method
        result = repository.create_pvc_access(1, "testuser")

        # Verify the interactions
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()

        # Verify the access entry was created with correct attributes
        created_access = mock_session.add.call_args[0][0]
        assert isinstance(created_access, StoragePVCAccess)
        assert created_access.pvc_id == 1
        assert created_access.username == "testuser"

    def test_clear_pvc_access(self, repository, mock_session):
        """
        GIVEN a repository and a PVC ID
        WHEN clear_pvc_access is called
        THEN it should delete all access entries for the PVC
        """
        # Call the method
        repository.clear_pvc_access(1)

        # Verify the interactions
        assert mock_session.query.called
        assert mock_session.query.return_value.filter.called
        assert mock_session.query.return_value.filter.return_value.delete.called
        mock_session.commit.assert_called_once()

    def test_get_pvc_access(self, repository, mock_session):
        """
        GIVEN a repository and a PVC ID
        WHEN get_pvc_access is called
        THEN it should return all access entries for the PVC
        """
        # Create mock access entries
        access1 = MagicMock(spec=StoragePVCAccess)
        access1.pvc_id = 1
        access1.username = "user1"

        access2 = MagicMock(spec=StoragePVCAccess)
        access2.pvc_id = 1
        access2.username = "user2"

        # Set up the mock to return the access entries
        mock_session.query.return_value.filter.return_value.all.return_value = [access1, access2]

        # Call the method
        result = repository.get_pvc_access(1)

        # Verify the result and interactions
        assert len(result) == 2
        assert result[0].username == "user1"
        assert result[1].username == "user2"
        assert mock_session.query.called
        assert mock_session.query.return_value.filter.called
        assert mock_session.query.return_value.filter.return_value.all.called

    def test_get_pvc_users(self, repository, mock_session):
        """
        GIVEN a repository and a PVC ID
        WHEN get_pvc_users is called
        THEN it should return all usernames with access to the PVC
        """
        # Create mock access entries
        access1 = MagicMock(spec=StoragePVCAccess)
        access1.username = "user1"

        access2 = MagicMock(spec=StoragePVCAccess)
        access2.username = "user2"

        # Set up the mock for get_pvc_access to return the access entries
        with patch.object(repository, "get_pvc_access", return_value=[access1, access2]):
            # Call the method
            result = repository.get_pvc_users(1)

            # Verify the result and interactions
            assert result == ["user1", "user2"]
            repository.get_pvc_access.assert_called_once_with(1)

    def test_is_pvc_in_use_true(self, repository, mock_session):
        """
        GIVEN a repository and a PVC ID that is in use
        WHEN is_pvc_in_use is called
        THEN it should return True
        """
        # Set up the mock to return a count of 1 (in use)
        mock_session.query.return_value.filter.return_value.count.return_value = 1

        # Call the method
        result = repository.is_pvc_in_use(1)

        # Verify the result and interactions
        assert result is True
        assert mock_session.query.called
        assert mock_session.query.return_value.filter.called
        assert mock_session.query.return_value.filter.return_value.count.called

    def test_is_pvc_in_use_false(self, repository, mock_session):
        """
        GIVEN a repository and a PVC ID that is not in use
        WHEN is_pvc_in_use is called
        THEN it should return False
        """
        # Set up the mock to return a count of 0 (not in use)
        mock_session.query.return_value.filter.return_value.count.return_value = 0

        # Call the method
        result = repository.is_pvc_in_use(1)

        # Verify the result and interactions
        assert result is False
        assert mock_session.query.called
        assert mock_session.query.return_value.filter.called
        assert mock_session.query.return_value.filter.return_value.count.called
