"""
Tests for the Rancher client.
"""

import pytest
import sys
import os
from unittest.mock import patch, MagicMock, call
import requests

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from clients.rancher import RancherClient, DesktopValues


class TestRancherClient:
    @pytest.fixture
    def rancher_client(self):
        """Create a RancherClient with mocked settings."""
        with patch("clients.rancher.get_settings") as mock_settings:
            settings = MagicMock()
            settings.RANCHER_API_URL = "https://rancher.example.com"
            settings.RANCHER_API_TOKEN = "test-token"
            settings.RANCHER_CLUSTER_ID = "test-cluster-id"
            settings.RANCHER_CLUSTER_NAME = "test-cluster"
            settings.RANCHER_PROJECT_ID = "test-project-id"
            settings.RANCHER_REPO_NAME = "test-repo"
            settings.NAMESPACE = "test-namespace"
            mock_settings.return_value = settings

            client = RancherClient()
            yield client

    def test_init(self):
        """Test initialization of RancherClient."""
        with patch("clients.rancher.get_settings") as mock_settings:
            # Arrange
            settings = MagicMock()
            settings.RANCHER_API_URL = "https://rancher.example.com"
            settings.RANCHER_API_TOKEN = "test-token"
            settings.RANCHER_CLUSTER_ID = "test-cluster-id"
            settings.RANCHER_CLUSTER_NAME = "test-cluster"
            settings.RANCHER_PROJECT_ID = "test-project-id"
            settings.RANCHER_REPO_NAME = "test-repo"
            settings.NAMESPACE = "test-namespace"
            mock_settings.return_value = settings

            # Act
            client = RancherClient()

            # Assert
            assert client.api_url == "https://rancher.example.com"
            assert client.api_token == "test-token"
            assert client.cluster_id == "test-cluster-id"
            assert client.cluster_name == "test-cluster"
            assert client.project_id == "test-project-id"
            assert client.repo_name == "test-repo"
            assert client.namespace == "test-namespace"
            assert client.headers["Authorization"] == "Bearer test-token"

    def test_install(self, rancher_client):
        """Test installing a desktop with Rancher."""
        with patch("requests.post") as mock_post:
            # Arrange
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"status": "success"}
            mock_post.return_value = mock_response

            connection_name = "test-desktop"
            desktop_values = DesktopValues(
                desktop="test-image:latest",
                name=connection_name,
                mincpu=1,
                maxcpu=4,
                minram="4096Mi",
                maxram="16384Mi",
                vnc_password="test-password",
                persistent_home=True,
            )

            # Act
            result = rancher_client.install(connection_name, desktop_values)

            # Assert
            assert result == {"status": "success"}
            mock_post.assert_called_once()

            # Verify URL and headers
            call_args = mock_post.call_args
            assert (
                "https://rancher.example.com/k8s/clusters/test-cluster-id/v1/catalog.cattle.io.clusterrepos/test-repo?action=install"
                in call_args[0][0]
            )
            assert call_args[1]["headers"] == rancher_client.headers

            # Verify payload contains expected values
            payload = call_args[1]["json"]
            assert payload["charts"][0]["releaseName"] == "test-desktop"
            assert payload["namespace"] == "test-namespace"

    def test_uninstall(self, rancher_client):
        """Test uninstalling a desktop with Rancher."""
        with patch("requests.post") as mock_post:
            # Arrange
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"status": "success"}
            mock_post.return_value = mock_response

            connection_name = "test-desktop"

            # Act
            result = rancher_client.uninstall(connection_name)

            # Assert
            assert result == {"status": "success"}
            mock_post.assert_called_once()

            # Verify URL and headers
            call_args = mock_post.call_args
            assert (
                "https://rancher.example.com/k8s/clusters/test-cluster-id/v1/catalog.cattle.io.apps/test-namespace/test-desktop?action=uninstall"
                in call_args[0][0]
            )
            assert call_args[1]["headers"] == rancher_client.headers

    def test_check_vnc_ready(self, rancher_client):
        """Test checking if VNC is ready."""
        with patch.object(rancher_client, "list_pods") as mock_list_pods:
            # Arrange - mock a running pod
            mock_pod = {
                "metadata": {"name": "test-desktop-0"},
                "status": {"phase": "Running", "containerStatuses": [{"ready": True}]},
            }
            mock_list_pods.return_value = [mock_pod]

            # Act
            result = rancher_client.check_vnc_ready("test-desktop", max_retries=1)

            # Assert
            assert result is True
            mock_list_pods.assert_called_once()

    def test_check_vnc_not_ready(self, rancher_client):
        """Test checking if VNC is not ready."""
        with patch.object(rancher_client, "list_pods") as mock_list_pods:
            # Arrange - mock a pod that is not ready
            mock_pod = {"metadata": {"name": "test-desktop-0"}, "status": {"phase": "Pending"}}
            mock_list_pods.return_value = [mock_pod]

            # Act
            result = rancher_client.check_vnc_ready("test-desktop", max_retries=1, retry_interval=0)

            # Assert
            assert result is False
            mock_list_pods.assert_called_once()

    def test_check_release_uninstalled(self, rancher_client):
        """Test checking if a release is uninstalled."""
        with patch.object(rancher_client, "list_releases") as mock_list_releases, patch.object(
            rancher_client, "list_pods"
        ) as mock_list_pods:
            # Arrange - release and pod not found
            mock_list_releases.return_value = [{"metadata": {"name": "other-release"}}]
            mock_list_pods.return_value = [{"metadata": {"name": "other-pod-0"}}]

            # Act
            result = rancher_client.check_release_uninstalled("test-desktop", max_retries=1, retry_interval=0)

            # Assert
            assert result is True
            mock_list_releases.assert_called_once()
            mock_list_pods.assert_called_once()

    def test_check_release_not_uninstalled(self, rancher_client):
        """Test checking if a release is not uninstalled (still exists)."""
        with patch.object(rancher_client, "list_releases") as mock_list_releases:
            # Arrange - release still exists
            mock_list_releases.return_value = [{"metadata": {"name": "test-desktop"}}]

            # Act
            result = rancher_client.check_release_uninstalled("test-desktop", max_retries=1, retry_interval=0)

            # Assert
            assert result is False
            mock_list_releases.assert_called_once()

    def test_get_pod_ip(self, rancher_client):
        """Test getting pod IP."""
        with patch("requests.get") as mock_get:
            # Arrange
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"data": [{"status": {"phase": "Running", "podIP": "10.0.0.1"}}]}
            mock_get.return_value = mock_response

            # Act
            result = rancher_client.get_pod_ip("test-desktop")

            # Assert
            assert result == "10.0.0.1"
            mock_get.assert_called_once()

    def test_list_releases(self, rancher_client):
        """Test listing Helm releases."""
        with patch("requests.get") as mock_get:
            # Arrange
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "data": [{"metadata": {"name": "test-desktop"}}, {"metadata": {"name": "other-desktop"}}]
            }
            mock_get.return_value = mock_response

            # Act
            result = rancher_client.list_releases()

            # Assert
            assert len(result) == 2
            assert result[0]["metadata"]["name"] == "test-desktop"
            assert result[1]["metadata"]["name"] == "other-desktop"
            mock_get.assert_called_once()

    def test_list_pods(self, rancher_client):
        """Test listing pods."""
        with patch("requests.get") as mock_get:
            # Arrange
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "data": [{"metadata": {"name": "test-desktop-0"}}, {"metadata": {"name": "other-desktop-0"}}]
            }
            mock_get.return_value = mock_response

            # Act
            result = rancher_client.list_pods()

            # Assert
            assert len(result) == 2
            assert result[0]["metadata"]["name"] == "test-desktop-0"
            assert result[1]["metadata"]["name"] == "other-desktop-0"
            mock_get.assert_called_once()

    def test_create_pvc(self, rancher_client):
        """Test creating a persistent volume claim."""
        with patch("requests.post") as mock_post:
            # Arrange
            mock_response = MagicMock()
            mock_response.status_code = 201
            mock_response.json.return_value = {"status": "success"}
            mock_post.return_value = mock_response

            # Act
            result = rancher_client.create_pvc("test-pvc", size="10Gi")

            # Assert
            assert result == {"status": "success"}
            mock_post.assert_called_once()

    def test_delete_pvc(self, rancher_client):
        """Test deleting a persistent volume claim."""
        with patch("requests.delete") as mock_delete:
            # Arrange
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"status": "success"}
            mock_delete.return_value = mock_response

            # Act
            result = rancher_client.delete_pvc("test-pvc")

            # Assert
            assert result == {"status": "success"}
            mock_delete.assert_called_once()
