import pytest
from unittest.mock import MagicMock, patch

@pytest.fixture
def mock_configs_client():
    """Mock the desktop configurations client."""
    with patch("app.clients.desktop_configurations.DesktopConfigurationsClient") as mock_client:
        client_instance = MagicMock()
        mock_client.return_value = client_instance
        yield client_instance

@pytest.fixture
def sample_configurations():
    """Sample desktop configuration data."""
    return [
        {
            "id": 1,
            "name": "Basic Desktop",
            "description": "Basic desktop configuration",
            "min_cpu": 1,
            "max_cpu": 2,
            "min_ram": "2048Mi",
            "max_ram": "4096Mi",
            "is_public": True,
            "image": "desktop:latest",
            "created_by": "admin",
        },
        {
            "id": 2,
            "name": "Advanced Desktop",
            "description": "Advanced desktop configuration",
            "min_cpu": 2,
            "max_cpu": 4,
            "min_ram": "4096Mi",
            "max_ram": "8192Mi",
            "is_public": False,
            "image": "desktop-advanced:latest",
            "created_by": "admin",
        }
    ]
