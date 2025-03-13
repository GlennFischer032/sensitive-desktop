"""Social Auth Configuration Module.

This module contains the configuration for python-social-auth integration with Flask.
It sets up the OIDC authentication pipeline and related settings.
"""

from typing import Any, Dict

from pydantic import Field
from pydantic_settings import BaseSettings


class SocialAuthConfig(BaseSettings):
    """Social Auth Configuration Settings."""

    # OIDC Provider Settings
    SOCIAL_AUTH_OIDC_PROVIDER_URL: str = Field(
        default="https://login.e-infra.cz/oidc", description="OIDC Provider URL"
    )
    SOCIAL_AUTH_OIDC_CLIENT_ID: str = Field(default="", description="OIDC Client ID")
    SOCIAL_AUTH_OIDC_CLIENT_SECRET: str = Field(default="", description="OIDC Client Secret")

    # Redirect URIs
    SOCIAL_AUTH_LOGIN_REDIRECT_URL: str = Field(
        default="/", description="URL to redirect to after successful login"
    )
    SOCIAL_AUTH_LOGIN_ERROR_URL: str = Field(
        default="/login", description="URL to redirect to on login error"
    )
    SOCIAL_AUTH_OIDC_CALLBACK_URL: str = Field(
        default="/api/auth/oidc/callback", description="OIDC callback URL path"
    )

    # JWT Settings
    SOCIAL_AUTH_JWT_ENABLED: bool = True
    SOCIAL_AUTH_JWT_ALGORITHM: str = "HS256"
    SOCIAL_AUTH_JWT_EXPIRATION: int = 3600  # 1 hour
    SOCIAL_AUTH_JWT_SECRET: str = Field(
        default="", description="JWT Secret key, should be same as SECRET_KEY"
    )

    class Config:
        env_file = ".env"
        case_sensitive = True


def get_social_auth_config() -> Dict[str, Any]:
    """Get the social auth configuration dictionary for Flask-Social-Auth."""
    config = SocialAuthConfig()

    return {
        "SOCIAL_AUTH_AUTHENTICATION_BACKENDS": (
            "social_core.backends.open_id_connect.OpenIdConnectAuth",
        ),
        # OIDC Settings
        "SOCIAL_AUTH_OIDC_OIDC_ENDPOINT": config.SOCIAL_AUTH_OIDC_PROVIDER_URL,
        "SOCIAL_AUTH_OIDC_KEY": config.SOCIAL_AUTH_OIDC_CLIENT_ID,
        "SOCIAL_AUTH_OIDC_SECRET": config.SOCIAL_AUTH_OIDC_CLIENT_SECRET,
        # Login URLs
        "SOCIAL_AUTH_LOGIN_REDIRECT_URL": config.SOCIAL_AUTH_LOGIN_REDIRECT_URL,
        "SOCIAL_AUTH_LOGIN_ERROR_URL": config.SOCIAL_AUTH_LOGIN_ERROR_URL,
        "SOCIAL_AUTH_OIDC_CALLBACK_URL": config.SOCIAL_AUTH_OIDC_CALLBACK_URL,
        # JWT Settings
        "SOCIAL_AUTH_JWT_ENABLED": config.SOCIAL_AUTH_JWT_ENABLED,
        "SOCIAL_AUTH_JWT_ALGORITHM": config.SOCIAL_AUTH_JWT_ALGORITHM,
        "SOCIAL_AUTH_JWT_EXPIRATION": config.SOCIAL_AUTH_JWT_EXPIRATION,
        "SOCIAL_AUTH_JWT_SECRET": config.SOCIAL_AUTH_JWT_SECRET,
        # User fields mapping
        "SOCIAL_AUTH_USER_FIELDS": ["username", "email", "organization"],
        "SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL": False,
        "SOCIAL_AUTH_CLEAN_USERNAME_FUNCTION": "desktop_manager.core.auth.clean_username",
        # Pipeline to create/update user from OIDC data
        "SOCIAL_AUTH_PIPELINE": (
            "social_core.pipeline.social_auth.social_details",
            "social_core.pipeline.social_auth.social_uid",
            "social_core.pipeline.social_auth.auth_allowed",
            "social_core.pipeline.social_auth.social_user",
            "social_core.pipeline.user.get_username",
            "desktop_manager.core.auth.create_user",  # Custom user creation
            "social_core.pipeline.social_auth.associate_user",
            "social_core.pipeline.social_auth.load_extra_data",
            "desktop_manager.core.auth.create_jwt_token",  # Custom JWT creation
        ),
    }
