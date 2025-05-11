import pytest
import sys
import os
from unittest.mock import patch, MagicMock, call
from sqlalchemy.exc import SQLAlchemyError

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from database.repositories.base import BaseRepository
from clients.base import APIError


# Create a mock model class for testing
class MockModel:
    """Mock SQLAlchemy model for testing BaseRepository."""

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


@pytest.fixture
def mock_session():
    """Mock SQLAlchemy session."""
    session = MagicMock()
    return session


@pytest.fixture
def base_repository(mock_session):
    """Create a BaseRepository instance with a mock session and MockModel."""
    return BaseRepository(mock_session, MockModel)


class TestBaseRepository:
    """Tests for BaseRepository class."""

    def test_init(self, mock_session):
        """Test repository initialization."""
        # Act
        repo = BaseRepository(mock_session, MockModel)

        # Assert
        assert repo.session is mock_session
        assert repo.model_class is MockModel
        assert repo.logger is not None

    def test_get_all_no_filters(self, base_repository, mock_session):
        """Test getting all entities without filters."""
        # Arrange
        mock_query = mock_session.query.return_value
        mock_items = [MockModel(id=1), MockModel(id=2)]
        mock_query.all.return_value = mock_items

        # Act
        result = base_repository.get_all()

        # Assert
        mock_session.query.assert_called_once_with(MockModel)
        mock_query.filter_by.assert_not_called()
        mock_query.all.assert_called_once()
        assert result == mock_items

    def test_get_all_with_filters(self, base_repository, mock_session):
        """Test getting entities with filters."""
        # Arrange
        mock_query = mock_session.query.return_value
        mock_filtered_query = mock_query.filter_by.return_value
        mock_items = [MockModel(id=1, name="test")]
        mock_filtered_query.all.return_value = mock_items

        # Act
        result = base_repository.get_all(name="test")

        # Assert
        mock_session.query.assert_called_once_with(MockModel)
        mock_query.filter_by.assert_called_once_with(name="test")
        mock_filtered_query.all.assert_called_once()
        assert result == mock_items

    def test_get_all_database_error(self, base_repository, mock_session):
        """Test handling database errors when getting entities."""
        # Arrange
        mock_session.query.side_effect = SQLAlchemyError("Database error")

        # Act & Assert
        with pytest.raises(APIError) as exc_info:
            base_repository.get_all()

        # Verify the error
        assert "Failed to get all MockModel" in str(exc_info.value)
        assert exc_info.value.status_code == 500

    def test_create_success(self, base_repository, mock_session):
        """Test successfully creating an entity."""
        # Arrange
        entity = MockModel(name="test")
        entity.id = 1  # ID would be set by the database

        # Act
        result = base_repository.create(entity)

        # Assert
        mock_session.add.assert_called_once_with(entity)
        mock_session.commit.assert_called_once()
        assert result is entity

    def test_create_database_error(self, base_repository, mock_session):
        """Test handling database errors when creating an entity."""
        # Arrange
        entity = MockModel(name="test")
        mock_session.commit.side_effect = SQLAlchemyError("Database error")

        # Act & Assert
        with pytest.raises(APIError) as exc_info:
            base_repository.create(entity)

        # Verify the error
        assert "Failed to create MockModel" in str(exc_info.value)
        assert exc_info.value.status_code == 500
        mock_session.rollback.assert_called_once()

    def test_update_success(self, base_repository, mock_session):
        """Test successfully updating an entity."""
        # Arrange
        entity = MockModel(id=1, name="test")

        # Act
        result = base_repository.update(entity)

        # Assert
        mock_session.commit.assert_called_once()
        assert result is entity

    def test_update_database_error(self, base_repository, mock_session):
        """Test handling database errors when updating an entity."""
        # Arrange
        entity = MockModel(id=1, name="test")
        mock_session.commit.side_effect = SQLAlchemyError("Database error")

        # Act & Assert
        with pytest.raises(APIError) as exc_info:
            base_repository.update(entity)

        # Verify the error
        assert "Failed to update MockModel" in str(exc_info.value)
        assert exc_info.value.status_code == 500
        mock_session.rollback.assert_called_once()
