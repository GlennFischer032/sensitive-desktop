"""Tests for the configuration routes."""
import json
from unittest.mock import patch, MagicMock

import pytest
from flask import url_for, template_rendered
from contextlib import contextmanager

from app.clients.base import APIError
from app.clients.desktop_configurations import DesktopConfigurationsClient


@pytest.fixture
def mock_configs_client():
    """Mock the desktop configurations client."""
    with patch(
        "app.configurations.routes.desktop_configs_client"
    ) as mock_client:
        yield mock_client


@pytest.fixture
def sample_configurations():
    """Return sample configuration data for testing."""
    return [
        {
            "id": 1,
            "name": "Test Configuration 1",
            "description": "Test Description 1",
            "image": "test-image-1:latest",
            "min_cpu": 1,
            "max_cpu": 4,
            "min_ram": "1024Mi",
            "max_ram": "4096Mi",
            "is_public": True,
            "allowed_users": [],
            "created_at": "2023-01-01T00:00:00Z",
            "updated_at": "2023-01-01T00:00:00Z",
        },
        {
            "id": 2,
            "name": "Test Configuration 2",
            "description": "Test Description 2",
            "image": "test-image-2:latest",
            "min_cpu": 2,
            "max_cpu": 8,
            "min_ram": "2048Mi",
            "max_ram": "8192Mi",
            "is_public": False,
            "allowed_users": ["user1", "user2"],
            "created_at": "2023-01-02T00:00:00Z",
            "updated_at": "2023-01-02T00:00:00Z",
        }
    ]


@pytest.fixture
def sample_users():
    """Return sample user data for testing."""
    return {
        "data": [
            {
                "id": 1,
                "username": "user1",
                "email": "user1@example.com",
                "is_admin": False,
            },
            {
                "id": 2,
                "username": "user2",
                "email": "user2@example.com",
                "is_admin": False,
            },
            {
                "id": 3,
                "username": "admin",
                "email": "admin@example.com",
                "is_admin": True,
            }
        ]
    }


@pytest.fixture
def admin_client(app):
    """Create a test client with admin privileges."""
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["token"] = "admin-token-12345"
            sess["username"] = "admin"
            sess["is_admin"] = True
            sess["logged_in"] = True
            sess.permanent = True
        yield client


@contextmanager
def captured_templates(app):
    """Capture templates rendered during test execution."""
    recorded = []
    def record(sender, template, context, **extra):
        recorded.append((template, context))
    template_rendered.connect(record, app)
    try:
        yield recorded
    finally:
        template_rendered.disconnect(record, app)


class TestBlueprintSetup:
    """Test the blueprint setup."""

    def test_configurations_blueprint(self):
        """Test that the configurations blueprint is correctly defined."""
        from app.configurations import configurations_bp
        assert configurations_bp.name == "configurations"
        assert configurations_bp.url_prefix == "/configurations"


class TestListConfigurations:
    """Test the list_configurations route."""

    def test_list_configurations_success(self, client, mock_configs_client, sample_configurations):
        """Test successful listing of configurations."""
        mock_configs_client.list_configurations.return_value = sample_configurations

        with patch("app.configurations.routes.render_template") as mock_render:
            mock_render.return_value = "mocked template"
            response = client.get(url_for("configurations.list_configurations"))

            assert response.status_code == 200
            mock_configs_client.list_configurations.assert_called_once()
            mock_render.assert_called_once_with("configurations.html", configurations=sample_configurations)

    def test_list_configurations_api_error(self, client, mock_configs_client):
        """Test handling of API error when listing configurations."""
        mock_configs_client.list_configurations.side_effect = APIError("API Error", status_code=500)

        with patch("app.configurations.routes.render_template") as mock_render:
            with patch("app.configurations.routes.flash") as mock_flash:
                mock_render.return_value = "mocked template"
                response = client.get(url_for("configurations.list_configurations"))

                assert response.status_code == 200
                mock_configs_client.list_configurations.assert_called_once()
                mock_flash.assert_called_once_with("Error listing configurations: API Error", "error")
                mock_render.assert_called_once_with("configurations.html", configurations=[])
