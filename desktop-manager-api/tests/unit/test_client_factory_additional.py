import unittest
from unittest.mock import patch, MagicMock

from clients.factory import ClientFactory
from clients.guacamole import GuacamoleClient
from clients.rancher import RancherClient


class TestClientFactoryAdditional(unittest.TestCase):
    """Additional test cases for ClientFactory class to improve coverage."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = ClientFactory()
        # Reset client instances between tests
        self.factory._guacamole_client = None
        self.factory._rancher_client = None

    @patch("clients.factory.get_settings")
    def test_initialization(self, mock_get_settings):
        """Test ClientFactory initialization."""
        mock_settings = MagicMock()
        mock_get_settings.return_value = mock_settings

        factory = ClientFactory()

        # Verify settings were loaded
        mock_get_settings.assert_called_once()
        self.assertEqual(factory.settings, mock_settings)

        # Verify clients initialized to None
        self.assertIsNone(factory._guacamole_client)
        self.assertIsNone(factory._rancher_client)

    @patch("clients.factory.GuacamoleClient")
    def test_get_guacamole_client_creates_new_instance(self, mock_guacamole_client):
        """Test get_guacamole_client creates a new client instance."""
        # Setup mock
        mock_instance = MagicMock(spec=GuacamoleClient)
        mock_guacamole_client.return_value = mock_instance

        # Act
        client = self.factory.get_guacamole_client()

        # Assert
        self.assertEqual(client, mock_instance)
        mock_guacamole_client.assert_called_once_with(
            guacamole_url=self.factory.settings.GUACAMOLE_URL,
        )

    @patch("clients.factory.GuacamoleClient")
    def test_get_guacamole_client_reuses_existing_instance(self, mock_guacamole_client):
        """Test get_guacamole_client reuses existing client instance."""
        # Setup mock existing instance
        existing_client = MagicMock(spec=GuacamoleClient)
        self.factory._guacamole_client = existing_client

        # Act
        client = self.factory.get_guacamole_client()

        # Assert
        self.assertEqual(client, existing_client)
        # Constructor should not be called again
        mock_guacamole_client.assert_not_called()

    @patch("clients.factory.RancherClient")
    def test_get_rancher_client_creates_new_instance(self, mock_rancher_client):
        """Test get_rancher_client creates a new client instance."""
        # Setup mock
        mock_instance = MagicMock(spec=RancherClient)
        mock_rancher_client.return_value = mock_instance

        # Act
        client = self.factory.get_rancher_client()

        # Assert
        self.assertEqual(client, mock_instance)
        mock_rancher_client.assert_called_once()

    @patch("clients.factory.RancherClient")
    def test_get_rancher_client_reuses_existing_instance(self, mock_rancher_client):
        """Test get_rancher_client reuses existing client instance."""
        # Setup mock existing instance
        existing_client = MagicMock(spec=RancherClient)
        self.factory._rancher_client = existing_client

        # Act
        client = self.factory.get_rancher_client()

        # Assert
        self.assertEqual(client, existing_client)
        # Constructor should not be called again
        mock_rancher_client.assert_not_called()
