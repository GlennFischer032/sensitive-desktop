"""Unit tests for the config module."""

import os
from unittest import mock

import pytest

from desktop_manager.config.config import Config


def test_config_defaults():
    """Test that Config has the expected default values."""
    # Create a clean environment
    with mock.patch.dict(os.environ, clear=True):
        config = Config()
        assert config.SECRET_KEY == ""
        assert config.POSTGRES_HOST == "localhost"
        assert config.POSTGRES_PORT == "5432"
        assert config.POSTGRES_DB == "desktop_manager"
        assert config.POSTGRES_USER == "guacamole_user"
        assert config.POSTGRES_PASSWORD == ""
        assert config.DATABASE_URL == "postgresql://guacamole_user:@localhost:5432/desktop_manager"
        assert config.GUACAMOLE_URL == "http://localhost:8080/guacamole"
        assert config.GUACAMOLE_USERNAME == ""
        assert config.GUACAMOLE_PASSWORD == ""
        assert config.NAMESPACE == ""
        assert config.ADMIN_USERNAME == ""
        assert config.ADMIN_PASSWORD == ""
        assert config.RANCHER_API_TOKEN == ""
        assert config.RANCHER_API_URL == ""
        assert config.RANCHER_CLUSTER_ID == ""
        assert config.RANCHER_REPO_NAME == ""
        assert config.DESKTOP_IMAGE == "cerit.io/desktops/ubuntu-xfce:22.04-user"


def test_config_from_env():
    """Test that Config reads values from environment variables."""
    test_values = {
        "SECRET_KEY": "test-secret-key",
        "POSTGRES_HOST": "test-postgres-host",
        "POSTGRES_PORT": "5433",
        "POSTGRES_DB": "test-db",
        "POSTGRES_USER": "test-user",
        "POSTGRES_PASSWORD": "test-password",
        "DATABASE_URL": "postgresql://test-user:test-password@test-postgres-host:5433/test-db",
        "GUACAMOLE_URL": "http://test-guacamole:8080/guacamole",
        "GUACAMOLE_USERNAME": "test-guacamole-username",
        "GUACAMOLE_PASSWORD": "test-guacamole-password",
        "NAMESPACE": "test-namespace",
        "ADMIN_USERNAME": "test-admin-username",
        "ADMIN_PASSWORD": "test-admin-password",
        "RANCHER_API_TOKEN": "test-rancher-api-token",
        "RANCHER_API_URL": "test-rancher-api-url",
        "RANCHER_CLUSTER_ID": "test-rancher-cluster-id",
        "RANCHER_REPO_NAME": "test-rancher-repo-name",
        "DESKTOP_IMAGE": "test-desktop-image",
    }

    with mock.patch.dict(os.environ, test_values):
        config = Config()
        assert config.SECRET_KEY == "test-secret-key"
        assert config.POSTGRES_HOST == "test-postgres-host"
        assert config.POSTGRES_PORT == "5433"
        assert config.POSTGRES_DB == "test-db"
        assert config.POSTGRES_USER == "test-user"
        assert config.POSTGRES_PASSWORD == "test-password"
        assert config.DATABASE_URL == "postgresql://test-user:test-password@test-postgres-host:5433/test-db"
        assert config.GUACAMOLE_URL == "http://test-guacamole:8080/guacamole"
        assert config.GUACAMOLE_USERNAME == "test-guacamole-username"
        assert config.GUACAMOLE_PASSWORD == "test-guacamole-password"
        assert config.NAMESPACE == "test-namespace"
        assert config.ADMIN_USERNAME == "test-admin-username"
        assert config.ADMIN_PASSWORD == "test-admin-password"
        assert config.RANCHER_API_TOKEN == "test-rancher-api-token"
        assert config.RANCHER_API_URL == "test-rancher-api-url"
        assert config.RANCHER_CLUSTER_ID == "test-rancher-cluster-id"
        assert config.RANCHER_REPO_NAME == "test-rancher-repo-name"
        assert config.DESKTOP_IMAGE == "test-desktop-image"


def test_database_url_construction():
    """Test that DATABASE_URL is constructed correctly if not provided."""
    env_vars = {
        "POSTGRES_HOST": "db-host",
        "POSTGRES_PORT": "5432",
        "POSTGRES_DB": "app-db",
        "POSTGRES_USER": "db-user",
        "POSTGRES_PASSWORD": "db-password",
    }

    with mock.patch.dict(os.environ, env_vars, clear=True):
        config = Config()
        assert config.DATABASE_URL == "postgresql://db-user:db-password@db-host:5432/app-db"
