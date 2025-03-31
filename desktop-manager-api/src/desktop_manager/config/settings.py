from functools import lru_cache
import os
import tempfile

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
    # Keep these for backward compatibility but they'll be phased out
    ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "")
    # New OIDC-based admin identification
    ADMIN_OIDC_SUB: str = os.getenv("ADMIN_OIDC_SUB", "")

    # Guacamole settings
    GUACAMOLE_URL: str = os.getenv("GUACAMOLE_URL", "http://guacamole:8080/guacamole")
    GUACAMOLE_USERNAME: str = os.getenv("GUACAMOLE_USERNAME", "guacadmin")
    GUACAMOLE_PASSWORD: str = os.getenv("GUACAMOLE_PASSWORD", "")
    GUACAMOLE_JSON_SECRET_KEY: str = os.getenv("GUACAMOLE_JSON_SECRET_KEY", "")
    GUACAMOLE_SECRET_KEY: str = os.getenv("GUACAMOLE_SECRET_KEY", "")
    EXTERNAL_GUACAMOLE_URL: str = os.getenv(
        "EXTERNAL_GUACAMOLE_URL", "http://localhost:8080/guacamole"
    )

    # Rancher settings
    RANCHER_API_TOKEN: str = os.getenv("RANCHER_API_TOKEN", "")
    RANCHER_API_URL: str = os.getenv("RANCHER_API_URL", "")
    RANCHER_CLUSTER_ID: str = os.getenv("RANCHER_CLUSTER_ID", "")
    RANCHER_CLUSTER_NAME: str = os.getenv("RANCHER_CLUSTER_NAME", "")
    RANCHER_PROJECT_ID: str = os.getenv("RANCHER_PROJECT_ID", "")
    RANCHER_REPO_NAME: str = os.getenv("RANCHER_REPO_NAME", "")
    NAMESPACE: str = os.getenv("NAMESPACE", "default")

    # Desktop settings
    DESKTOP_IMAGE: str = os.getenv("DESKTOP_IMAGE", "cerit.io/desktops/ubuntu-xfce:22.04-user")

    # OIDC settings
    OIDC_PROVIDER_URL: str = os.getenv(
        "SOCIAL_AUTH_OIDC_PROVIDER_URL", "https://login.e-infra.cz/oidc"
    )
    OIDC_CLIENT_ID: str = os.getenv("SOCIAL_AUTH_OIDC_CLIENT_ID", "")
    OIDC_CLIENT_SECRET: str = os.getenv("SOCIAL_AUTH_OIDC_CLIENT_SECRET", "")
    OIDC_BACKEND_REDIRECT_URI: str = os.getenv(
        "SOCIAL_AUTH_OIDC_CALLBACK_URL", "http://localhost:5000/api/auth/oidc/callback"
    )
    OIDC_REDIRECT_URI: str = os.getenv(
        "SOCIAL_AUTH_OIDC_FRONTEND_REDIRECT_URI", "http://localhost:5001/auth/oidc/callback"
    )
    FRONTEND_URL: str = os.getenv("FRONTEND_URL", "http://localhost:5001")
    CORS_ALLOWED_ORIGINS: str = os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:5001")

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
