"""Unit tests for the config module."""

import os
from unittest import mock

import pytest

from desktop_manager.config.settings import Settings


def test_config_defaults():
    """Test that Settings has the expected default values."""
    # Create a clean environment
    clean_env = {}  # Empty environment to ensure no host environment variables affect the test
    with mock.patch.dict(os.environ, clean_env, clear=True):
        config = Settings()
        assert config.SECRET_KEY == "dev_secret_key_123"
        assert config.POSTGRES_HOST == "postgres"
        assert config.POSTGRES_PORT == 5432
        assert config.POSTGRES_DATABASE == "desktop_manager"
        assert config.POSTGRES_USER == "guacamole_user"
        assert config.POSTGRES_PASSWORD == "guacpass"
        assert config.GUACAMOLE_URL == "http://guacamole:8080/guacamole"
        assert config.GUACAMOLE_USERNAME == "guacadmin"
        assert config.GUACAMOLE_PASSWORD == "guacadmin"
        assert config.NAMESPACE == "fischer-ns"
        assert config.ADMIN_USERNAME == "admin"
        assert config.ADMIN_PASSWORD == "admin123"
        assert config.RANCHER_API_TOKEN == "token-58z6j:jrkfmqfms2gdlzqv98v8zjfck8nq672fgz2j2jv6t9q67txsds22wc"
        assert config.RANCHER_API_URL == "https://rancher.cloud.e-infra.cz"
        assert config.RANCHER_CLUSTER_ID == "c-m-qvndqhf6"
        assert config.RANCHER_REPO_NAME == "cerit-sc"
        assert config.DESKTOP_IMAGE == "cerit.io/desktops/ubuntu-xfce:22.04-user"
        # Verify the DATABASE_URL property works correctly
        assert config.database_url == f"postgresql://{config.POSTGRES_USER}:{config.POSTGRES_PASSWORD}@{config.POSTGRES_HOST}:{config.POSTGRES_PORT}/{config.POSTGRES_DATABASE}"


def test_config_from_env():
    """Test that Settings reads values from environment variables."""
    test_values = {
        "SECRET_KEY": "test-secret-key",
        "POSTGRES_HOST": "test-postgres-host",
        "POSTGRES_PORT": "5433",
        "POSTGRES_DATABASE": "test-db",
        "POSTGRES_USER": "test-user",
        "POSTGRES_PASSWORD": "test-password",
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
        config = Settings()
        assert config.SECRET_KEY == "test-secret-key"
        assert config.POSTGRES_HOST == "test-postgres-host"
        assert config.POSTGRES_PORT == 5433
        assert config.POSTGRES_DATABASE == "test-db"
        assert config.POSTGRES_USER == "test-user"
        assert config.POSTGRES_PASSWORD == "test-password"
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
        # Verify the DATABASE_URL property uses the updated values
        assert config.database_url == "postgresql://test-user:test-password@test-postgres-host:5433/test-db"
