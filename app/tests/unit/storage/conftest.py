import pytest
from unittest.mock import MagicMock, patch

@pytest.fixture
def mock_storage_client():
    """Mock storage client."""
    with patch("app.clients.factory.client_factory.get_storage_client") as mock:
        client_instance = MagicMock()
        mock.return_value = client_instance
        yield client_instance

@pytest.fixture
def sample_pvcs():
    """Sample PVC data."""
    return [
        {
            "id": 1,
            "name": "test-pvc-1",
            "size": "10Gi",
            "status": "Bound",
            "created_by": "admin",
            "created_at": "2023-01-01T12:00:00Z",
        },
        {
            "id": 2,
            "name": "test-pvc-2",
            "size": "20Gi",
            "status": "Bound",
            "created_by": "user1",
            "created_at": "2023-01-02T12:00:00Z",
        }
    ]
