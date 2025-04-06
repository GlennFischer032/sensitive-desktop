"""Unit tests for the rancher client module."""

from dataclasses import dataclass, field
import json
from unittest.mock import Mock, patch

import pytest
import requests

from desktop_manager.clients.base import APIError
from desktop_manager.clients.rancher import RancherClient


@dataclass
class DesktopValues:
    """Desktop values for Helm chart installation."""

    desktop: str
    name: str
    vnc_password: str
    image: str = field(default="")

    def __post_init__(self):
        """Set image to desktop value if not provided."""
        if not self.image:
            self.image = self.desktop

    def to_dict(self) -> dict:
        """Convert to dictionary for API call."""
        return {
            "desktop": self.desktop,
            "name": self.name,
            "password": self.vnc_password,
            "image": self.image,
        }


@pytest.fixture
def mock_settings():
    """Provide mock settings."""
    with patch("desktop_manager.clients.rancher.get_settings") as mock_get_settings:
        settings = Mock()
        settings.RANCHER_API_URL = "https://rancher.example.com"
        settings.RANCHER_API_TOKEN = "test-token"
        settings.RANCHER_CLUSTER_ID = "test-cluster"
        settings.RANCHER_REPO_NAME = "test-repo"
        settings.NAMESPACE = "test-namespace"
        settings.DESKTOP_IMAGE = "test-image:latest"
        mock_get_settings.return_value = settings
        yield settings


@pytest.fixture
def mock_requests_post():
    """Mock requests.post."""
    with patch("desktop_manager.clients.rancher.requests.post") as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "success"}
        mock_post.return_value = mock_response
        yield mock_post


@pytest.fixture
def mock_requests_get():
    """Mock requests.get."""
    with patch("desktop_manager.clients.rancher.requests.get") as mock_get:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": []}
        mock_get.return_value = mock_response
        yield mock_get


@pytest.fixture
def rancher_client(mock_settings):
    """Create a RancherClient instance."""
    return RancherClient()


def test_install_success(rancher_client, mock_requests_post):
    """Test successful Helm chart installation."""
    # Create test values
    values = DesktopValues(
        desktop="test-desktop", name="test-connection", vnc_password="test-password"
    )

    # Mock the response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "success"}
    mock_response.text = json.dumps({"status": "success"})
    mock_requests_post.return_value = mock_response

    # Call install method
    result = rancher_client.install("test-connection", values)

    # Verify result
    assert result == {"status": "success"}

    # Verify requests.post was called with correct arguments
    mock_requests_post.assert_called_once()
    args, kwargs = mock_requests_post.call_args
    assert (
        args[0]
        == "https://rancher.example.com/k8s/clusters/test-cluster/v1/catalog.cattle.io.clusterrepos/test-repo?action=install"
    )
    assert kwargs["headers"] == {
        "Authorization": "Bearer test-token",
        "Content-Type": "application/json",
    }

    # Verify the structure of the JSON payload
    assert kwargs["json"]["namespace"] == "test-namespace"
    assert kwargs["json"]["charts"][0]["releaseName"] == "test-connection"
    assert kwargs["json"]["charts"][0]["chartName"] == "desktop"
    assert kwargs["json"]["charts"][0]["version"] == "0.4"

    # Verify the values are included in the payload
    assert "values" in kwargs["json"]["charts"][0]
    values_dict = kwargs["json"]["charts"][0]["values"]
    assert values_dict["name"] == "test-connection"
    assert values_dict["password"] == "test-password"
    assert values_dict["image"] == "test-desktop"  # image is set to desktop value in __post_init__


def test_install_error(rancher_client, mock_requests_post):
    """Test Helm chart installation error."""
    # Configure mock to return an error
    mock_requests_post.return_value.status_code = 500
    mock_requests_post.return_value.text = "Internal Server Error"

    # Create test values
    values = DesktopValues(
        desktop="test-desktop", name="test-connection", vnc_password="test-password"
    )

    # Call install method and verify it raises an APIError
    with pytest.raises(APIError) as excinfo:
        rancher_client.install("test-connection", values)

    # Verify error message
    assert "Failed to install Helm chart" in str(excinfo.value)
    assert excinfo.value.status_code == 500


def test_install_request_exception(rancher_client, mock_requests_post):
    """Test Helm chart installation with request exception."""
    # Configure mock to raise an exception
    mock_requests_post.side_effect = requests.RequestException("Connection error")

    # Create test values
    values = DesktopValues(
        desktop="test-desktop", name="test-connection", vnc_password="test-password"
    )

    # Call install method and verify it raises an APIError
    with pytest.raises(APIError) as excinfo:
        rancher_client.install("test-connection", values)

    # Verify error message
    assert "Failed to install Helm chart" in str(excinfo.value)
    assert excinfo.value.status_code == 500


def test_uninstall_success(rancher_client, mock_requests_post):
    """Test successful Helm chart uninstallation."""
    # Call uninstall method
    result = rancher_client.uninstall("test-connection")

    # Verify result
    assert result == {"status": "success"}

    # Verify requests.post was called with correct arguments
    mock_requests_post.assert_called_once()
    args, kwargs = mock_requests_post.call_args
    assert "test-connection" in args[0]
    assert "uninstall" in args[0]
    assert kwargs["headers"] == {
        "Authorization": "Bearer test-token",
        "Content-Type": "application/json",
    }
    assert kwargs["json"] == {}


def test_uninstall_error(rancher_client, mock_requests_post):
    """Test Helm chart uninstallation error."""
    # Configure mock to return an error
    mock_requests_post.return_value.status_code = 500
    mock_requests_post.return_value.text = "Internal Server Error"

    # Call uninstall method and verify it raises an APIError
    with pytest.raises(APIError) as excinfo:
        rancher_client.uninstall("test-connection")

    # Verify error message
    assert "Failed to uninstall Helm chart" in str(excinfo.value)
    assert excinfo.value.status_code == 500


def test_check_vnc_ready_success(rancher_client, mock_requests_get):
    """Test successful VNC readiness check."""
    # Configure mock to return a ready pod that matches the expected name format
    name_prefix = "test-connection"

    # The test connection pods have a specific naming pattern: name-0 (ending with -0)
    expected_pod_name = f"{name_prefix}-0"

    mock_requests_get.return_value.json.return_value = {
        "data": [
            {
                "metadata": {
                    "name": expected_pod_name,  # The pod name must match exactly what check_vnc_ready looks for
                },
                "status": {
                    "phase": "Running",
                    "containerStatuses": [
                        {
                            "ready": True,
                        },
                    ],
                },
            },
        ],
    }

    # Set the max_retries to a higher value to allow more attempts
    result = rancher_client.check_vnc_ready(name_prefix, max_retries=3)

    # Verify result
    assert result is True


def test_check_vnc_ready_not_found(rancher_client, mock_requests_get):
    """Test VNC readiness check when pod is not found."""
    # Configure mock to return no pods
    mock_requests_get.return_value.json.return_value = {"data": []}

    # Call check_vnc_ready method
    result = rancher_client.check_vnc_ready("test-connection", max_retries=1)

    # Verify result
    assert result is False


def test_check_vnc_ready_not_running(rancher_client, mock_requests_get):
    """Test VNC readiness check when pod is not running."""
    # Configure mock to return a pod that is not running
    mock_requests_get.return_value.json.return_value = {
        "data": [
            {
                "metadata": {
                    "name": "test-connection-abc123-0",
                },
                "status": {
                    "phase": "Pending",
                    "containerStatuses": [],
                },
            },
        ],
    }

    # Call check_vnc_ready method
    result = rancher_client.check_vnc_ready("test-connection", max_retries=1)

    # Verify result
    assert result is False


def test_check_vnc_ready_not_ready(rancher_client, mock_requests_get):
    """Test VNC readiness check when containers are not ready."""
    # Configure mock to return a pod with containers that are not ready
    mock_requests_get.return_value.json.return_value = {
        "data": [
            {
                "metadata": {
                    "name": "test-connection-abc123-0",
                },
                "status": {
                    "phase": "Running",
                    "containerStatuses": [
                        {
                            "ready": False,
                        },
                    ],
                },
            },
        ],
    }

    # Call check_vnc_ready method
    result = rancher_client.check_vnc_ready("test-connection", max_retries=1)

    # Verify result
    assert result is False


def test_get_pod_ip_success(rancher_client, mock_requests_get):
    """Test successful pod IP retrieval."""
    # Configure mock to return a pod with an IP
    mock_requests_get.return_value.json.return_value = {
        "data": [
            {
                "status": {
                    "phase": "Running",
                    "podIP": "10.0.0.1",
                },
            },
        ],
    }

    # Call get_pod_ip method
    result = rancher_client.get_pod_ip("test-connection")

    # Verify result
    assert result == "10.0.0.1"

    # Verify requests.get was called with correct arguments
    mock_requests_get.assert_called_once()
    args, kwargs = mock_requests_get.call_args
    assert "pod" in args[0]
    assert "test-connection" in args[0]
    assert kwargs["headers"] == {
        "Authorization": "Bearer test-token",
        "Content-Type": "application/json",
    }


def test_get_pod_ip_not_found(rancher_client, mock_requests_get):
    """Test pod IP retrieval when pod is not found."""
    # Configure mock to return no pods
    mock_requests_get.return_value.json.return_value = {"data": []}

    # Call get_pod_ip method
    result = rancher_client.get_pod_ip("test-connection")

    # Verify result
    assert result is None


def test_get_pod_ip_error(rancher_client, mock_requests_get):
    """Test pod IP retrieval error."""
    # Configure mock to return an error
    mock_requests_get.return_value.status_code = 500
    mock_requests_get.return_value.text = "Internal Server Error"

    # Call get_pod_ip method and verify it raises an APIError
    with pytest.raises(APIError) as excinfo:
        rancher_client.get_pod_ip("test-connection")

    # Verify error message
    assert "Failed to get pod IP" in str(excinfo.value)
    assert excinfo.value.status_code == 500


def test_list_releases_success(rancher_client, mock_requests_get):
    """Test successful release listing."""
    # Configure mock to return releases
    mock_requests_get.return_value.json.return_value = {
        "data": [
            {"name": "release1"},
            {"name": "release2"},
        ],
    }

    # Call list_releases method
    result = rancher_client.list_releases()

    # Verify result
    assert len(result) == 2
    assert result[0]["name"] == "release1"
    assert result[1]["name"] == "release2"

    # Verify requests.get was called with correct arguments
    mock_requests_get.assert_called_once()
    args, kwargs = mock_requests_get.call_args
    assert "catalog.cattle.io.apps" in args[0]
    assert kwargs["headers"] == {
        "Authorization": "Bearer test-token",
        "Content-Type": "application/json",
    }


def test_list_releases_error(rancher_client, mock_requests_get):
    """Test release listing error."""
    # Configure mock to return an error
    mock_requests_get.return_value.status_code = 500
    mock_requests_get.return_value.text = "Internal Server Error"

    # Call list_releases method and verify it raises an APIError
    with pytest.raises(APIError) as excinfo:
        rancher_client.list_releases()

    # Verify error message
    assert "Failed to list releases" in str(excinfo.value)
    assert excinfo.value.status_code == 500


def test_get_release_success(rancher_client, mock_requests_get):
    """Test successful release retrieval."""
    # Configure mock to return a release
    mock_requests_get.return_value.json.return_value = {"name": "test-connection"}

    # Call get_release method
    result = rancher_client.get_release("test-connection")

    # Verify result
    assert result["name"] == "test-connection"

    # Verify requests.get was called with correct arguments
    mock_requests_get.assert_called_once()
    args, kwargs = mock_requests_get.call_args
    assert "catalog.cattle.io.apps" in args[0]
    assert "test-connection" in args[0]
    assert kwargs["headers"] == {
        "Authorization": "Bearer test-token",
        "Content-Type": "application/json",
    }


def test_get_release_error(rancher_client, mock_requests_get):
    """Test release retrieval error."""
    # Configure mock to return an error
    mock_requests_get.return_value.status_code = 500
    mock_requests_get.return_value.text = "Internal Server Error"

    # Call get_release method and verify it raises an APIError
    with pytest.raises(APIError) as excinfo:
        rancher_client.get_release("test-connection")

    # Verify error message
    assert "Failed to get release" in str(excinfo.value)
    assert excinfo.value.status_code == 500
