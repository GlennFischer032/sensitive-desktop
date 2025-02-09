from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache
import os
from typing import Optional

class Settings(BaseSettings):
    # Database settings
    MYSQL_HOST: str = os.getenv("MYSQL_HOST", "localhost")
    MYSQL_PORT: int = int(os.getenv("MYSQL_PORT", "3306"))
    MYSQL_DATABASE: str = os.getenv("MYSQL_DATABASE", "guacamole_db")
    MYSQL_USER: str = os.getenv("MYSQL_USER", "guacamole_user")
    MYSQL_PASSWORD: str = os.getenv("MYSQL_PASSWORD", "")

    # Application settings
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your_secret_key")
    ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "")

    # Guacamole settings
    GUACAMOLE_API_URL: str = os.getenv("GUACAMOLE_API_URL", "http://guacamole:8080/guacamole")
    GUACAMOLE_USERNAME: str = os.getenv("GUACAMOLE_USERNAME", "guacadmin")
    GUACAMOLE_PASSWORD: str = os.getenv("GUACAMOLE_PASSWORD", "")

    # Rancher settings
    RANCHER_API_TOKEN: str = os.getenv("RANCHER_API_TOKEN", "")
    RANCHER_API_URL: str = os.getenv("RANCHER_API_URL", "")
    RANCHER_CLUSTER_ID: str = os.getenv("RANCHER_CLUSTER_ID", "")
    RANCHER_REPO_NAME: str = os.getenv("RANCHER_REPO_NAME", "")
    NAMESPACE: str = os.getenv("NAMESPACE", "default")

    # Desktop settings
    DESKTOP_IMAGE: str = os.getenv("DESKTOP_IMAGE", "cerit.io/desktops/ubuntu-xfce:22.04-user")
    TEMP_VALUES_FILE_PATH: str = os.getenv("TEMP_VALUES_FILE_PATH", "/tmp/values.yaml")

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True)

@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance.
    
    Returns:
        Settings: The application settings instance
    """
    return Settings() 