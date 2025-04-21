"""
Tests for route handler functions by directly mocking their dependencies.
"""

import pytest
import sys
import os
from unittest.mock import patch, MagicMock
import json

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))


def test_token_service_create_token():
    """Test TokenService.create_token method is called with correct parameters and returns expected result."""
    from services.token import TokenService

    # Arrange
    with patch.object(TokenService, "create_token") as mock_create_token:
        mock_create_token.return_value = {
            "token": "mocked.jwt.token",
            "token_id": "test-token-id",
            "name": "Test Token",
            "expires_at": "2023-12-31T12:00:00Z",
            "created_by": "admin_user",
        }

        service = TokenService()
        data = {"name": "Test Token", "description": "Test description", "expires_in_days": 30}
        current_user = MagicMock(username="admin_user")
        session = MagicMock()

        # Act
        result = service.create_token(data, current_user, session)

        # Assert
        assert "token" in result
        assert result["token"] == "mocked.jwt.token"
        assert result["token_id"] == "test-token-id"
        assert result["name"] == "Test Token"
        assert "expires_at" in result
        assert result["created_by"] == "admin_user"

        # Verify mock was called with correct parameters
        mock_create_token.assert_called_once_with(data, current_user, session)


def test_token_service_list_tokens():
    """Test TokenService.list_tokens method is called with correct parameters and returns expected result."""
    from services.token import TokenService

    # Arrange
    with patch.object(TokenService, "list_tokens") as mock_list_tokens:
        mock_list_tokens.return_value = {
            "tokens": [
                {
                    "token_id": "test-token-id-1",
                    "name": "Test Token 1",
                    "description": "Test description 1",
                    "created_at": "2023-01-01T12:00:00Z",
                    "expires_at": "2023-12-31T12:00:00Z",
                    "created_by": "admin_user",
                    "revoked": False,
                },
                {
                    "token_id": "test-token-id-2",
                    "name": "Test Token 2",
                    "description": "Test description 2",
                    "created_at": "2023-02-01T12:00:00Z",
                    "expires_at": "2023-12-31T12:00:00Z",
                    "created_by": "admin_user",
                    "revoked": False,
                },
            ]
        }

        service = TokenService()
        current_user = MagicMock(username="admin_user")
        session = MagicMock()

        # Act
        result = service.list_tokens(current_user, session)

        # Assert
        assert "tokens" in result
        assert len(result["tokens"]) == 2
        assert result["tokens"][0]["token_id"] == "test-token-id-1"
        assert result["tokens"][1]["token_id"] == "test-token-id-2"

        # Verify mock was called with correct parameters
        mock_list_tokens.assert_called_once_with(current_user, session)


def test_token_service_revoke_token():
    """Test TokenService.revoke_token method is called with correct parameters and returns expected result."""
    from services.token import TokenService

    # Arrange
    with patch.object(TokenService, "revoke_token") as mock_revoke_token:
        mock_revoke_token.return_value = {"message": "Token successfully revoked"}

        service = TokenService()
        token_id = "test-token-id"
        session = MagicMock()

        # Act
        result = service.revoke_token(token_id, session)

        # Assert
        assert "message" in result
        assert result["message"] == "Token successfully revoked"

        # Verify mock was called with correct parameters
        mock_revoke_token.assert_called_once_with(token_id, session)


def test_token_service_api_login():
    """Test TokenService.api_login method is called with correct parameters and returns expected result."""
    from services.token import TokenService

    # Arrange
    with patch.object(TokenService, "api_login") as mock_api_login:
        mock_api_login.return_value = {"username": "admin_user", "is_admin": True, "email": "admin@example.com"}

        service = TokenService()
        token = "valid.jwt.token"
        session = MagicMock()

        # Act
        result = service.api_login(token, session)

        # Assert
        assert "username" in result
        assert result["username"] == "admin_user"
        assert "is_admin" in result
        assert result["is_admin"] is True
        assert "email" in result
        assert result["email"] == "admin@example.com"

        # Verify mock was called with correct parameters
        mock_api_login.assert_called_once_with(token, session)
