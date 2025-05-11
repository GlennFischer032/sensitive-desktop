import unittest
from unittest.mock import patch, MagicMock

from clients.factory import ClientFactory
from clients.guacamole import GuacamoleClient
from clients.rancher import RancherClient


class TestClientFactory(unittest.TestCase):
    """Test cases for ClientFactory class."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = ClientFactory()
        # Reset the client instances for each test
        self.factory._guacamole_client = None
        self.factory._rancher_client = None

    @patch("clients.factory.GuacamoleClient")
    def test_get_guacamole_client_new_instance(self, mock_guacamole):
        """Test get_guacamole_client creates a new instance when none exists."""
        mock_instance = MagicMock(spec=GuacamoleClient)
        mock_guacamole.return_value = mock_instance

        # First call should create a new instance
        client = self.factory.get_guacamole_client()

        # Verify that GuacamoleClient constructor was called
        mock_guacamole.assert_called_once()
        self.assertEqual(client, mock_instance)

    @patch("clients.factory.GuacamoleClient")
    def test_get_guacamole_client_existing_instance(self, mock_guacamole):
        """Test get_guacamole_client reuses existing instance."""
        # Set up an existing instance
        mock_existing = MagicMock(spec=GuacamoleClient)
        self.factory._guacamole_client = mock_existing

        # Call should return existing instance
        client = self.factory.get_guacamole_client()

        # Verify constructor wasn't called again
        mock_guacamole.assert_not_called()
        self.assertEqual(client, mock_existing)

    @patch("clients.factory.RancherClient")
    def test_get_rancher_client_new_instance(self, mock_rancher):
        """Test get_rancher_client creates a new instance when none exists."""
        mock_instance = MagicMock(spec=RancherClient)
        mock_rancher.return_value = mock_instance

        # First call should create a new instance
        client = self.factory.get_rancher_client()

        # Verify that RancherClient constructor was called
        mock_rancher.assert_called_once()
        self.assertEqual(client, mock_instance)

    @patch("clients.factory.RancherClient")
    def test_get_rancher_client_existing_instance(self, mock_rancher):
        """Test get_rancher_client reuses existing instance."""
        # Set up an existing instance
        mock_existing = MagicMock(spec=RancherClient)
        self.factory._rancher_client = mock_existing

        # Call should return existing instance
        client = self.factory.get_rancher_client()

        # Verify constructor wasn't called again
        mock_rancher.assert_not_called()
        self.assertEqual(client, mock_existing)
