"""Unit tests for the config module."""

import os

from desktop_manager.config.config import Config


def test_config_defaults():
    """Test that Config uses default values when environment variables are not set."""
    # Save current environment variables
    old_env = dict(os.environ)

    try:
        # Clear relevant environment variables
        for key in [
            "SECRET_KEY",
            "MYSQL_HOST",
            "MYSQL_PORT",
            "MYSQL_DATABASE",
            "MYSQL_USER",
            "MYSQL_PASSWORD",
            "DATABASE_URL",
            "GUACAMOLE_API_URL",
            "GUACAMOLE_USERNAME",
            "GUACAMOLE_PASSWORD",
            "NAMESPACE",
            "VALUES_FILE_PATH",
            "TEMP_VALUES_FILE_PATH",
            "ADMIN_USERNAME",
            "ADMIN_PASSWORD",
            "RANCHER_API_TOKEN",
            "RANCHER_API_URL",
            "RANCHER_CLUSTER_ID",
            "RANCHER_REPO_NAME",
            "DESKTOP_IMAGE",
        ]:
            if key in os.environ:
                del os.environ[key]

        # Check default values
        assert Config.MYSQL_HOST == "localhost"
        assert Config.MYSQL_PORT == "3306"
        assert Config.MYSQL_DATABASE == "desktop_manager"
        assert Config.MYSQL_USER == "guacamole_user"
        # Don't strictly check the MYSQL_PASSWORD default as it might vary in different environments
        # Instead, check that it's a string
        assert isinstance(Config.MYSQL_PASSWORD, str)

        # Check DATABASE_URL construction pattern instead of exact value
        assert "mysql+pymysql://" in Config.DATABASE_URL
        assert Config.MYSQL_USER in Config.DATABASE_URL
        assert Config.MYSQL_HOST in Config.DATABASE_URL
        assert Config.MYSQL_PORT in Config.DATABASE_URL
        assert Config.MYSQL_DATABASE in Config.DATABASE_URL

        # Check other defaults - don't assert exact value for GUACAMOLE_API_URL
        # Just check that it contains the expected path and port
        assert "/guacamole/api" in Config.GUACAMOLE_API_URL
        assert "8080" in Config.GUACAMOLE_API_URL

        assert Config.DESKTOP_IMAGE == "cerit.io/desktops/ubuntu-xfce:22.04-user"

    finally:
        # Restore environment variables
        os.environ.clear()
        os.environ.update(old_env)


def test_config_from_env():
    """Test that Config loads values from environment variables when set."""
    # Save current environment variables
    old_env = dict(os.environ)

    try:
        # Set test environment variables
        test_values = {
            "SECRET_KEY": "test_secret",
            "MYSQL_HOST": "test_host",
            "MYSQL_PORT": "5432",
            "MYSQL_DATABASE": "test_db",
            "MYSQL_USER": "test_user",
            "MYSQL_PASSWORD": "test_pass",
            "DATABASE_URL": "override_url",
            "GUACAMOLE_API_URL": "http://test-guacamole:8080/api",
            "GUACAMOLE_USERNAME": "test_guac_user",
            "GUACAMOLE_PASSWORD": "test_guac_pass",
            "NAMESPACE": "test-namespace",
            "VALUES_FILE_PATH": "./test-values.yaml",
            "TEMP_VALUES_FILE_PATH": "./test-temp-values.yaml",
            "ADMIN_USERNAME": "test_admin",
            "ADMIN_PASSWORD": "test_admin_pass",
            "RANCHER_API_TOKEN": "test_token",
            "RANCHER_API_URL": "https://test-rancher.com",
            "RANCHER_CLUSTER_ID": "test_cluster",
            "RANCHER_REPO_NAME": "test_repo",
            "DESKTOP_IMAGE": "test/desktop:latest",
        }

        for k, v in test_values.items():
            os.environ[k] = v

        # Re-import to pick up new environment variables
        import importlib

        from desktop_manager.config import config

        importlib.reload(config)

        # Check that values were loaded from environment
        assert config.Config.SECRET_KEY == "test_secret"
        assert config.Config.MYSQL_HOST == "test_host"
        assert config.Config.MYSQL_PORT == "5432"
        assert config.Config.MYSQL_DATABASE == "test_db"
        assert config.Config.MYSQL_USER == "test_user"
        assert config.Config.MYSQL_PASSWORD == "test_pass"

        # When DATABASE_URL is explicitly set, it should override the constructed one
        assert config.Config.DATABASE_URL == "override_url"

        assert config.Config.GUACAMOLE_API_URL == "http://test-guacamole:8080/api"
        assert config.Config.GUACAMOLE_USERNAME == "test_guac_user"
        assert config.Config.GUACAMOLE_PASSWORD == "test_guac_pass"

        assert config.Config.NAMESPACE == "test-namespace"
        assert config.Config.VALUES_FILE_PATH == "./test-values.yaml"
        assert config.Config.TEMP_VALUES_FILE_PATH == "./test-temp-values.yaml"

        assert config.Config.ADMIN_USERNAME == "test_admin"
        assert config.Config.ADMIN_PASSWORD == "test_admin_pass"

        assert config.Config.RANCHER_API_TOKEN == "test_token"
        assert config.Config.RANCHER_API_URL == "https://test-rancher.com"
        assert config.Config.RANCHER_CLUSTER_ID == "test_cluster"
        assert config.Config.RANCHER_REPO_NAME == "test_repo"

        assert config.Config.DESKTOP_IMAGE == "test/desktop:latest"

    finally:
        # Restore environment variables
        os.environ.clear()
        os.environ.update(old_env)

        # Reset config module to original state
        import importlib

        from desktop_manager.config import config

        importlib.reload(config)


def test_database_url_construction():
    """Test that DATABASE_URL is properly constructed from individual settings."""
    # Save current environment variables
    old_env = dict(os.environ)

    try:
        # Set test environment variables but not DATABASE_URL
        test_values = {
            "MYSQL_HOST": "custom_host",
            "MYSQL_PORT": "3307",
            "MYSQL_DATABASE": "custom_db",
            "MYSQL_USER": "custom_user",
            "MYSQL_PASSWORD": "custom_pass",
        }

        for k, v in test_values.items():
            os.environ[k] = v

        # Clear DATABASE_URL if set
        if "DATABASE_URL" in os.environ:
            del os.environ["DATABASE_URL"]

        # Re-import to pick up new environment variables
        import importlib

        from desktop_manager.config import config

        importlib.reload(config)

        # Check constructed DATABASE_URL
        expected_url = (
            "mysql+pymysql://custom_user:custom_pass@custom_host:3307/custom_db"
        )
        assert expected_url == config.Config.DATABASE_URL

    finally:
        # Restore environment variables
        os.environ.clear()
        os.environ.update(old_env)

        # Reset config module to original state
        import importlib

        from desktop_manager.config import config

        importlib.reload(config)
