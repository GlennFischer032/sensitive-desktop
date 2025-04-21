import pytest
import sys
import os
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from database.repositories.token import TokenRepository
from database.models.token import Token


@pytest.fixture
def mock_session():
    """Create a mock session for testing."""
    session = MagicMock()

    # Mock query builder
    query = MagicMock()
    session.query.return_value = query

    # Mock filter
    filter_query = MagicMock()
    query.filter.return_value = filter_query

    # Mock first
    filter_query.first.return_value = None  # Default to None, override in tests

    # Mock order_by
    filter_query.order_by.return_value = filter_query

    # Mock all
    filter_query.all.return_value = []  # Default to empty list, override in tests

    # Return session mock
    return session


def test_get_by_token_id(mock_session):
    """Test getting a token by token_id."""
    # Arrange
    token_id = "test-token-id"

    # Mock token in response
    token = Token(
        token_id=token_id, name="Test Token", expires_at=datetime.utcnow() + timedelta(days=30), created_by="admin_user"
    )

    # Setup mock to return the token
    filter_query = mock_session.query.return_value.filter.return_value
    filter_query.first.return_value = token

    # Create repository
    repo = TokenRepository(mock_session)

    # Act
    result = repo.get_by_token_id(token_id)

    # Assert
    assert result == token
    mock_session.query.assert_called_once_with(Token)
    mock_session.query.return_value.filter.assert_called_once()


def test_create_token(mock_session):
    """Test creating a token."""
    # Arrange
    name = "Test Token"
    description = "Test description"
    expires_in_days = 30
    created_by = "admin_user"

    # Setup mock
    mock_session.add.return_value = None
    mock_session.commit.return_value = None

    # Setup a return value for the token creation
    def side_effect(token):
        # Set these attributes to match what we expect TokenRepository.create to do
        token.revoked = False
        mock_session.add(token)
        return token

    # Create repository
    repo = TokenRepository(mock_session)

    # Mock BaseRepository.create to apply side_effect
    with patch("database.repositories.base.BaseRepository.create", side_effect=side_effect):
        # Mock uuid
        with patch("database.repositories.token.uuid") as mock_uuid:
            mock_uuid.uuid4.return_value = "test-token-id"
            result = repo.create_token(name, description, expires_in_days, created_by)

    # Assert
    assert result.token_id == "test-token-id"
    assert result.name == name
    assert result.description == description
    assert result.created_by == created_by
    assert result.revoked is False

    # Verify session interaction
    mock_session.add.assert_called_once()


def test_revoke_token(mock_session):
    """Test revoking a token."""
    # Arrange
    token_id = "test-token-id"

    # Create token for the test
    token = Token(
        token_id=token_id,
        name="Test Token",
        expires_at=datetime.utcnow() + timedelta(days=30),
        created_by="admin_user",
        revoked=False,
    )

    # Setup mock to return the token
    filter_query = mock_session.query.return_value.filter.return_value
    filter_query.first.return_value = token

    # Create repository
    repo = TokenRepository(mock_session)

    # Act
    result = repo.revoke_token(token_id)

    # Assert
    assert result == token
    assert result.revoked is True
    assert result.revoked_at is not None
    mock_session.query.assert_called_once_with(Token)
    mock_session.commit.assert_called_once()


def test_revoke_token_not_found(mock_session):
    """Test revoking a token that doesn't exist."""
    # Arrange
    token_id = "non-existent-token"

    # Setup mock to return None
    filter_query = mock_session.query.return_value.filter.return_value
    filter_query.first.return_value = None

    # Create repository
    repo = TokenRepository(mock_session)

    # Act
    result = repo.revoke_token(token_id)

    # Assert
    assert result is None
    mock_session.query.assert_called_once_with(Token)
    mock_session.commit.assert_not_called()


def test_update_last_used(mock_session):
    """Test updating the last_used timestamp."""
    # Arrange
    token_id = "test-token-id"

    # Create token for the test
    token = Token(
        token_id=token_id,
        name="Test Token",
        expires_at=datetime.utcnow() + timedelta(days=30),
        created_by="admin_user",
        last_used=None,
    )

    # Setup mock to return the token
    filter_query = mock_session.query.return_value.filter.return_value
    filter_query.first.return_value = token

    # Create repository
    repo = TokenRepository(mock_session)

    # Act
    result = repo.update_last_used(token_id)

    # Assert
    assert result == token
    assert result.last_used is not None
    mock_session.query.assert_called_once_with(Token)
    mock_session.commit.assert_called_once()


def test_get_valid_tokens(mock_session):
    """Test getting valid tokens."""
    # Arrange
    created_by = "admin_user"

    # Create tokens for the test
    token1 = Token(
        token_id="test-token-id-1",
        name="Test Token 1",
        expires_at=datetime.utcnow() + timedelta(days=30),
        created_by=created_by,
        revoked=False,
    )

    token2 = Token(
        token_id="test-token-id-2",
        name="Test Token 2",
        expires_at=datetime.utcnow() + timedelta(days=60),
        created_by=created_by,
        revoked=False,
    )

    # Setup mock to return the tokens
    query = mock_session.query.return_value
    filter_query = query.filter.return_value
    filter_query.filter.return_value = filter_query  # For the second filter
    order_by_query = filter_query.order_by.return_value
    order_by_query.all.return_value = [token1, token2]

    # Create repository
    repo = TokenRepository(mock_session)

    # Act
    result = repo.get_valid_tokens(created_by)

    # Assert
    assert len(result) == 2
    assert result[0] == token1
    assert result[1] == token2
    mock_session.query.assert_called_once_with(Token)


def test_get_tokens_for_user(mock_session):
    """Test getting tokens for a specific user."""
    # Arrange
    username = "admin_user"

    # Create tokens for the test
    token1 = Token(
        token_id="test-token-id-1",
        name="Test Token 1",
        expires_at=datetime.utcnow() + timedelta(days=30),
        created_by=username,
        revoked=False,
    )

    token2 = Token(
        token_id="test-token-id-2",
        name="Test Token 2",
        expires_at=datetime.utcnow() + timedelta(days=60),
        created_by=username,
        revoked=False,
    )

    # Setup mock to return the tokens
    query = mock_session.query.return_value
    filter_query = query.filter.return_value
    order_by_query = filter_query.order_by.return_value
    order_by_query.all.return_value = [token1, token2]

    # Create repository
    repo = TokenRepository(mock_session)

    # Act
    result = repo.get_tokens_for_user(username)

    # Assert
    assert len(result) == 2
    assert result[0] == token1
    assert result[1] == token2
    mock_session.query.assert_called_once_with(Token)
    query.filter.assert_called_once()
    filter_query.order_by.assert_called_once()


def test_is_token_valid(mock_session):
    """Test checking if a token is valid."""
    # Arrange
    token_id = "test-token-id"

    # Create token for the test
    token = Token(
        token_id=token_id,
        name="Test Token",
        expires_at=datetime.utcnow() + timedelta(days=30),  # Not expired
        created_by="admin_user",
        revoked=False,  # Not revoked
    )

    # Setup mock to return the token
    filter_query = mock_session.query.return_value.filter.return_value
    filter_query.first.return_value = token

    # Create repository
    repo = TokenRepository(mock_session)

    # Act
    result = repo.is_token_valid(token_id)

    # Assert
    assert result is True
    mock_session.query.assert_called_once_with(Token)


def test_is_token_valid_revoked(mock_session):
    """Test checking if a revoked token is valid."""
    # Arrange
    token_id = "test-token-id"

    # Create token for the test - revoked
    token = Token(
        token_id=token_id,
        name="Test Token",
        expires_at=datetime.utcnow() + timedelta(days=30),
        created_by="admin_user",
        revoked=True,  # Revoked
    )

    # Setup mock to return the token
    filter_query = mock_session.query.return_value.filter.return_value
    filter_query.first.return_value = token

    # Create repository
    repo = TokenRepository(mock_session)

    # Act
    result = repo.is_token_valid(token_id)

    # Assert
    assert result is False
    mock_session.query.assert_called_once_with(Token)


def test_is_token_valid_expired(mock_session):
    """Test checking if an expired token is valid."""
    # Arrange
    token_id = "test-token-id"

    # Create token for the test - expired
    token = Token(
        token_id=token_id,
        name="Test Token",
        expires_at=datetime.utcnow() - timedelta(days=1),  # Expired
        created_by="admin_user",
        revoked=False,
    )

    # Setup mock to return the token
    filter_query = mock_session.query.return_value.filter.return_value
    filter_query.first.return_value = token

    # Create repository
    repo = TokenRepository(mock_session)

    # Act
    result = repo.is_token_valid(token_id)

    # Assert
    assert result is False
    mock_session.query.assert_called_once_with(Token)


def test_is_token_valid_not_found(mock_session):
    """Test checking if a non-existent token is valid."""
    # Arrange
    token_id = "non-existent-token"

    # Setup mock to return None
    filter_query = mock_session.query.return_value.filter.return_value
    filter_query.first.return_value = None

    # Create repository
    repo = TokenRepository(mock_session)

    # Act
    result = repo.is_token_valid(token_id)

    # Assert
    assert result is False
    mock_session.query.assert_called_once_with(Token)
