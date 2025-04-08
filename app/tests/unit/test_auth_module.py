"""
Unit tests for the auth module functionality.
"""

import pytest
import requests
from http import HTTPStatus
from unittest.mock import patch, MagicMock
from app.services.auth.auth import (
    AuthError,
    RateLimitError,
    logout,
    is_authenticated,
    get_current_user,
    refresh_token,
)


class TestAuthError:
    def test_auth_error_defaults(self):
        """Test AuthError with default values"""
        error = AuthError("Authentication failed")

        assert error.message == "Authentication failed"
        assert error.status_code == HTTPStatus.UNAUTHORIZED
        assert str(error) == "Authentication failed"

    def test_auth_error_custom_status(self):
        """Test AuthError with custom status code"""
        error = AuthError("Invalid token", HTTPStatus.FORBIDDEN)

        assert error.message == "Invalid token"
        assert error.status_code == HTTPStatus.FORBIDDEN
        assert str(error) == "Invalid token"


class TestRateLimitError:
    def test_rate_limit_error(self):
        """Test RateLimitError has correct status and inheritance"""
        error = RateLimitError(60)

        assert error.message == "Rate limit exceeded. Please try again in 60 seconds."
        assert error.status_code == HTTPStatus.TOO_MANY_REQUESTS
        assert isinstance(error, AuthError)
        assert str(error) == "Rate limit exceeded. Please try again in 60 seconds."


class TestSessionFunctions:
    @pytest.fixture
    def app_context(self, app):
        """Provide app context for the tests"""
        with app.app_context():
            with app.test_request_context():
                yield

    @patch("app.services.auth.auth.session")
    def test_logout(self, mock_session, app_context):
        """Test logout function clears the session"""
        # Setup session state with a regular MagicMock instead of AsyncMock
        mock_session.clear = MagicMock()

        # Call logout
        logout()

        # Verify session was cleared
        mock_session.clear.assert_called_once()

    @patch("app.services.auth.auth.session")
    def test_is_authenticated_true(self, mock_session, app_context):
        """Test is_authenticated returns True when logged in"""
        # Setup session state with a regular MagicMock instead of AsyncMock
        mock_session.get = MagicMock(return_value=True)

        # Check authentication status
        result = is_authenticated()

        # Verify result
        assert result is True
        mock_session.get.assert_called_once_with("logged_in", False)

    @patch("app.services.auth.auth.session")
    def test_is_authenticated_false(self, mock_session, app_context):
        """Test is_authenticated returns False when not logged in"""
        # Setup session state with a regular MagicMock instead of AsyncMock
        mock_session.get = MagicMock(return_value=False)

        # Check authentication status
        result = is_authenticated()

        # Verify result
        assert result is False
        mock_session.get.assert_called_once_with("logged_in", False)

    @patch("app.services.auth.auth.session")
    def test_get_current_user_authenticated(self, mock_session, app_context):
        """Test get_current_user returns user data when authenticated"""
        mock_session.get.side_effect = lambda key, default=None: {
            "logged_in": True,
            "username": "test-user",
            "is_admin": False,
        }.get(key, default)

        mock_session.__getitem__.side_effect = lambda key: {
            "username": "test-user",
            "is_admin": False,
        }[key]

        user = get_current_user()

        assert user.get("username") == "test-user"
        assert user.get("is_admin") == False

    @patch("app.services.auth.auth.session")
    @patch("app.services.auth.auth.is_authenticated")
    def test_get_current_user_unauthenticated(self, mock_is_authenticated, mock_session, app_context):
        """Test get_current_user returns None when not authenticated"""
        # Setup unauthenticated state
        mock_is_authenticated.return_value = False

        # Get current user
        user = get_current_user()

        # Verify result is None
        assert user is None
        mock_is_authenticated.assert_called_once()


class TestRefreshToken:
    @pytest.fixture
    def app_context(self, app):
        """Provide app context for the tests"""
        with app.app_context():
            with app.test_request_context():
                yield

    @patch("app.services.auth.auth.session")
    @patch("app.services.auth.auth.is_authenticated")
    @patch("app.clients.factory.client_factory.get_auth_client")
    def test_refresh_token_success(self, mock_get_auth_client, mock_is_authenticated, mock_session, app_context):
        """Test successful token refresh"""
        # Setup authenticated state
        mock_is_authenticated.return_value = True
        mock_session.get.return_value = "old-token"

        # Setup auth client response
        mock_auth_client = MagicMock()
        mock_auth_client.refresh_token.return_value = (
            {"token": "new-token", "user": {"username": "test-user"}},
            HTTPStatus.OK,
        )
        mock_get_auth_client.return_value = mock_auth_client

        # Call refresh token
        refresh_token()

        # Verify token was updated in session
        mock_session.__setitem__.assert_called_once_with("token", "new-token")

    @patch("app.services.auth.auth.is_authenticated")
    def test_refresh_token_not_authenticated(self, mock_is_authenticated, app_context):
        """Test token refresh when not authenticated"""
        # Setup unauthenticated state
        mock_is_authenticated.return_value = False

        # Call refresh token and expect AuthError
        with pytest.raises(AuthError) as excinfo:
            refresh_token()

        # Verify error message
        assert str(excinfo.value) == "Not authenticated"
        assert excinfo.value.status_code == HTTPStatus.UNAUTHORIZED

    @patch("app.services.auth.auth.session")
    @patch("app.services.auth.auth.is_authenticated")
    @patch("app.clients.factory.client_factory.get_auth_client")
    def test_refresh_token_request_error(self, mock_get_auth_client, mock_is_authenticated, mock_session, app_context):
        """Test token refresh with request error"""
        # Setup authenticated state
        mock_is_authenticated.return_value = True
        mock_session.get.return_value = "old-token"

        # Setup auth client to raise error
        mock_auth_client = MagicMock()
        mock_auth_client.refresh_token.side_effect = requests.exceptions.RequestException("Network error")
        mock_get_auth_client.return_value = mock_auth_client

        # Call refresh token and expect AuthError
        with pytest.raises(AuthError) as excinfo:
            refresh_token()

        # Verify error message
        assert "Network error" in str(excinfo.value)
        assert excinfo.value.status_code == HTTPStatus.UNAUTHORIZED

        # Verify logout was called
        mock_session.clear.assert_called_once()

    @patch("app.services.auth.auth.session")
    @patch("app.services.auth.auth.is_authenticated")
    @patch("app.clients.factory.client_factory.get_auth_client")
    def test_refresh_token_auth_error(self, mock_get_auth_client, mock_is_authenticated, mock_session, app_context):
        """Test token refresh with auth error response"""
        # Setup authenticated state
        mock_is_authenticated.return_value = True
        mock_session.get.return_value = "old-token"

        # Setup auth client error response
        mock_auth_client = MagicMock()
        mock_auth_client.refresh_token.return_value = ({"error": "Invalid token"}, HTTPStatus.UNAUTHORIZED)
        mock_get_auth_client.return_value = mock_auth_client

        # Call refresh token - no token update should happen
        refresh_token()

        # Verify token was NOT updated in session (no __setitem__ call)
        mock_session.__setitem__.assert_not_called()
