"""
Tests for services to improve coverage.
"""

import pytest
import sys
import os
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))


@pytest.fixture
def app():
    """Create a Flask app for testing."""
    from flask import Flask

    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = "test-secret-key"
    app.config["JWT_ALGORITHM"] = "HS256"
    return app


class TestTokenService:
    """Tests for the TokenService."""

    @pytest.fixture
    def token_repo_mock(self):
        """Mock TokenRepository."""
        with patch("services.token.TokenRepository") as mock:
            mock_instance = MagicMock()

            # Mock create_token
            token = MagicMock()
            token.token_id = "test-token-id"
            token.name = "Test Token"
            token.description = "Test description"
            token.created_at = datetime.utcnow()
            token.expires_at = datetime.utcnow() + timedelta(days=30)
            token.created_by = "admin_user"
            token.revoked = False
            mock_instance.create_token.return_value = token

            # Mock get_by_id
            mock_instance.get_by_id.return_value = token

            # Mock get_by_token_id
            mock_instance.get_by_token_id.return_value = token

            # Mock get_tokens_for_user
            token2 = MagicMock()
            token2.token_id = "test-token-id-2"
            token2.name = "Test Token 2"
            token2.description = "Test description 2"
            token2.created_at = datetime.utcnow()
            token2.expires_at = datetime.utcnow() + timedelta(days=60)
            token2.created_by = "admin_user"
            token2.revoked = False

            mock_instance.get_tokens_for_user.return_value = [token, token2]

            # Mock revoke_token
            mock_instance.revoke_token.return_value = token

            # Mock is_token_valid
            mock_instance.is_token_valid.return_value = True

            # Return mock
            mock.return_value = mock_instance
            yield mock_instance

    @pytest.fixture
    def user_repo_mock(self):
        """Mock UserRepository."""
        with patch("services.token.UserRepository") as mock:
            mock_instance = MagicMock()

            # Mock get_by_username
            user = MagicMock()
            user.username = "admin_user"
            user.email = "admin@example.com"
            user.is_admin = True
            mock_instance.get_by_username.return_value = user

            # Return mock
            mock.return_value = mock_instance
            yield mock_instance

    @pytest.fixture
    def jwt_mock(self):
        """Mock JWT."""
        with patch("services.token.jwt") as mock:
            # Mock encode
            mock.encode.return_value = "mocked.jwt.token"

            # Mock decode
            mock.decode.return_value = {
                "sub": "token:test-token-id",
                "name": "admin_user",
                "token_id": "test-token-id",
                "iat": datetime.utcnow(),
                "exp": datetime.utcnow() + timedelta(days=30),
                "admin": True,
            }

            yield mock

    def test_create_token(self, app, token_repo_mock, jwt_mock):
        """Test creating a token."""
        from services.token import TokenService

        # Arrange
        service = TokenService()
        data = {"name": "Test Token", "description": "Test description", "expires_in_days": 30}
        current_user = MagicMock()
        current_user.username = "admin_user"
        session = MagicMock()

        # Run in app context
        with app.app_context():
            # Act
            result = service.create_token(data, current_user, session)

        # Assert
        assert result["token"] == "mocked.jwt.token"
        assert result["token_id"] == "test-token-id"
        assert result["name"] == "Test Token"
        assert "expires_at" in result
        assert result["created_by"] == "admin_user"

        # Verify mocks
        token_repo_mock.create_token.assert_called_once()
        jwt_mock.encode.assert_called_once()

    def test_list_tokens(self, token_repo_mock):
        """Test listing tokens."""
        from services.token import TokenService

        # Arrange
        service = TokenService()
        current_user = MagicMock()
        current_user.username = "admin_user"
        session = MagicMock()

        # Act
        result = service.list_tokens(current_user, session)

        # Assert
        assert "tokens" in result
        assert len(result["tokens"]) == 2
        assert result["tokens"][0]["token_id"] == "test-token-id"
        assert result["tokens"][1]["token_id"] == "test-token-id-2"

        # Verify mocks
        token_repo_mock.get_tokens_for_user.assert_called_once_with("admin_user")

    def test_revoke_token(self, token_repo_mock):
        """Test revoking a token."""
        from services.token import TokenService

        # Arrange
        service = TokenService()
        token_id = "test-token-id"
        session = MagicMock()

        # Act
        result = service.revoke_token(token_id, session)

        # Assert
        assert "message" in result
        assert result["message"] == "Token successfully revoked"

        # Verify mocks
        token_repo_mock.get_by_id.assert_called_once_with(token_id)
        token_repo_mock.revoke_token.assert_called_once_with(token_id)

    def test_api_login(self, app, token_repo_mock, user_repo_mock, jwt_mock):
        """Test API login."""
        from services.token import TokenService

        # Arrange
        service = TokenService()
        token = "valid.jwt.token"
        session = MagicMock()

        # Run in app context
        with app.app_context():
            # Act
            result = service.api_login(token, session)

        # Assert
        assert "username" in result
        assert result["username"] == "admin_user"
        assert "is_admin" in result
        assert result["is_admin"] is True
        assert "email" in result
        assert result["email"] == "admin@example.com"

        # Verify mocks
        jwt_mock.decode.assert_called_once()
        token_repo_mock.get_by_token_id.assert_called_once_with("test-token-id")
        user_repo_mock.get_by_username.assert_called_once_with("admin_user")


class TestStoragePVCService:
    """Tests for the StoragePVCService."""

    @pytest.fixture
    def settings_mock(self):
        """Mock settings."""
        with patch("services.storage_pvc.get_settings") as mock:
            settings = MagicMock()
            settings.RANCHER_API_URL = "https://rancher.example.com/v3"
            settings.RANCHER_API_TOKEN = "test-token"
            settings.RANCHER_CLUSTER_ID = "c-abcde"
            settings.RANCHER_PROJECT_ID = "p-12345"
            settings.RANCHER_NAMESPACE = "test-namespace"
            mock.return_value = settings
            yield settings

    @pytest.fixture
    def rancher_client_mock(self):
        """Mock RancherClient."""
        with patch("services.storage_pvc.client_factory") as factory_mock:
            rancher_client = MagicMock()

            # Mock get_pvc
            rancher_client.get_pvc.return_value = {
                "metadata": {"name": "test-pvc", "namespace": "test-namespace"},
                "status": {"phase": "Bound"},
            }

            factory_mock.get_rancher_client.return_value = rancher_client
            yield rancher_client

    @pytest.fixture
    def storage_pvc_repo_mock(self):
        """Mock StoragePVCRepository."""
        with patch("services.storage_pvc.StoragePVCRepository") as mock:
            mock_instance = MagicMock()

            # Mock get_by_id
            pvc = MagicMock()
            pvc.id = 1
            pvc.name = "test-pvc"
            pvc.namespace = "test-namespace"
            pvc.size = "10Gi"
            pvc.status = "Bound"
            pvc.created_by = "admin"
            pvc.created_at = datetime.utcnow()
            pvc.is_public = True
            pvc.to_dict.return_value = {
                "id": 1,
                "name": "test-pvc",
                "namespace": "test-namespace",
                "size": "10Gi",
                "status": "Bound",
                "created_at": pvc.created_at.isoformat(),
                "created_by": "admin",
                "is_public": True,
            }
            mock_instance.get_by_id.return_value = pvc

            # Mock get_pvc_users
            mock_instance.get_pvc_users.return_value = ["user1", "user2"]

            # Return mock
            mock.return_value = mock_instance
            yield mock_instance

    @pytest.fixture
    def connection_repo_mock(self):
        """Mock ConnectionRepository."""
        with patch("services.storage_pvc.ConnectionRepository") as mock:
            mock_instance = MagicMock()

            # Mock get_by_pvc_id
            conn = MagicMock()
            conn.id = 1
            conn.type = "desktop"
            conn.name = "desktop-1"
            conn.owner = "admin"
            conn.to_dict.return_value = {"id": 1, "type": "desktop", "name": "desktop-1", "owner": "admin"}
            mock_instance.get_by_pvc_id.return_value = [conn]

            # Return mock
            mock.return_value = mock_instance
            yield mock_instance

    def test_get_storage_pvc_by_id(self, storage_pvc_repo_mock, rancher_client_mock, settings_mock):
        """Test getting a storage PVC by ID."""
        from services.storage_pvc import StoragePVCService

        # Arrange
        service = StoragePVCService()
        pvc_id = 1
        session = MagicMock()

        # Act
        result = service.get_storage_pvc_by_id(pvc_id, session)

        # Assert
        assert "pvc" in result
        assert result["pvc"]["id"] == 1
        assert result["pvc"]["name"] == "test-pvc"
        assert result["pvc"]["size"] == "10Gi"

        # Verify mocks
        storage_pvc_repo_mock.get_by_id.assert_called_once_with(pvc_id)

    def test_get_pvc_connections(self, storage_pvc_repo_mock, connection_repo_mock, rancher_client_mock, settings_mock):
        """Test getting connections for a PVC."""
        from services.storage_pvc import StoragePVCService

        # Arrange
        service = StoragePVCService()
        pvc_id = 1
        session = MagicMock()

        # Create mock connections with the necessary attributes
        connection = MagicMock()
        connection.id = 1
        connection.name = "desktop-1"
        connection.created_at = datetime.utcnow()
        connection.created_by = "admin"
        connection.is_stopped = False

        # Ensure the connection_repo_mock.get_connections_for_pvc returns our mock connections
        connection_repo_mock.get_connections_for_pvc.return_value = [connection]

        # Act
        result = service.get_pvc_connections(pvc_id, session)

        # Assert
        assert "connections" in result
        assert len(result["connections"]) == 1
        assert result["connections"][0]["id"] == 1
        assert result["connections"][0]["name"] == "desktop-1"

        # Verify mocks
        storage_pvc_repo_mock.get_by_id.assert_not_called()  # This function doesn't call get_by_id
        connection_repo_mock.get_connections_for_pvc.assert_called_once_with(pvc_id)
