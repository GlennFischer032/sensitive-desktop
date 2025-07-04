from functools import lru_cache
import os

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Database settings
    POSTGRES_HOST: str = os.getenv("POSTGRES_HOST", "postgres")
    POSTGRES_PORT: int = int(os.getenv("POSTGRES_PORT", "5432"))
    POSTGRES_DATABASE: str = os.getenv("POSTGRES_DATABASE", "desktop_manager")
    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "guacamole_user")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "")

    # Application settings
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev_secret_key_123")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    # New OIDC-based admin identification
    ADMIN_OIDC_SUB: str = os.getenv("ADMIN_OIDC_SUB", "")

    # Guacamole settings
    GUACAMOLE_URL: str = os.getenv("GUACAMOLE_URL", "http://guacamole:8080/guacamole")
    GUACAMOLE_JSON_SECRET_KEY: str = os.getenv("GUACAMOLE_JSON_SECRET_KEY", "")
    GUACAMOLE_SECRET_KEY: str = os.getenv("GUACAMOLE_SECRET_KEY", "")
    EXTERNAL_GUACAMOLE_URL: str = os.getenv("EXTERNAL_GUACAMOLE_URL", "http://localhost:8080/guacamole")

    # Rancher settings
    RANCHER_API_TOKEN: str = os.getenv("RANCHER_API_TOKEN", "")
    RANCHER_API_URL: str = os.getenv("RANCHER_API_URL", "")
    RANCHER_CLUSTER_ID: str = os.getenv("RANCHER_CLUSTER_ID", "")
    RANCHER_CLUSTER_NAME: str = os.getenv("RANCHER_CLUSTER_NAME", "kuba-cluster")
    RANCHER_PROJECT_ID: str = os.getenv("RANCHER_PROJECT_ID", "")
    RANCHER_REPO_NAME: str = os.getenv("RANCHER_REPO_NAME", "")
    NAMESPACE: str = os.getenv("NAMESPACE", "default")
    GUACAMOLE_RELEASE_NAME: str = os.getenv("GUACAMOLE_RELEASE_NAME", "guacamole")

    # Kubernetes settings
    KUBECONFIG: str = os.getenv("KUBECONFIG", "")

    # Desktop settings
    DESKTOP_IMAGE: str = os.getenv("DESKTOP_IMAGE", "cerit.io/desktops/ubuntu-xfce:22.04-user")

    # OIDC settings
    OIDC_PROVIDER_URL: str = os.getenv("OIDC_PROVIDER_URL", "https://login.e-infra.cz/oidc")
    OIDC_CLIENT_ID: str = os.getenv("OIDC_CLIENT_ID", "")
    OIDC_CLIENT_SECRET: str = os.getenv("OIDC_CLIENT_SECRET", "")
    OIDC_CALLBACK_URL: str = os.getenv("OIDC_CALLBACK_URL", "http://localhost:5001/auth/oidc/callback")
    CORS_ALLOWED_ORIGINS: str = os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:5001")
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

    @property
    def database_url(self) -> str:
        """Get the database URL constructed from the Postgres settings.

        Returns:
            str: The database connection URL
        """
        return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DATABASE}"

    model_config = SettingsConfigDict(env_file=None, case_sensitive=True)


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance.

    Returns:
        Settings: The application settings instance
    """
    return Settings()
