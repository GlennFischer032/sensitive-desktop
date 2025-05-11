"""Guacamole client module for desktop-manager-api.

This module provides a client for interacting with Apache Guacamole.
"""

import logging

from clients.base import APIError, BaseClient
from config.settings import get_settings
from pydantic import BaseModel
import requests


def to_kebab(s: str) -> str:  # "swap_red_blue" -> "swap-red-blue"
    return s.replace("_", "-")


class GuacamoleConnectionParameters(BaseModel):
    hostname: str
    port: str
    password: str
    disable_copy: str = "true"
    disable_paste: str = "false"

    # Pydantic v1
    class Config:
        alias_generator = to_kebab
        allow_population_by_field_name = True

    def model_dump(self, **kw):
        kw.setdefault("by_alias", True)
        kw.setdefault("exclude_none", True)
        kw.setdefault("exclude_defaults", False)
        kw.setdefault("exclude_unset", False)
        return super().model_dump(**kw)


class GuacamoleClient(BaseClient):
    """Client for interacting with Apache Guacamole.

    This client provides methods for:
    - Authentication
    - User management
    - Connection management
    - Group management
    - Permission management
    """

    def __init__(
        self,
        guacamole_url: str | None = None,
    ):
        """Initialize GuacamoleClient.

        Args:
            guacamole_url: Guacamole base URL
            username: Guacamole admin username
            password: Guacamole admin password
            data_source: Guacamole data source
        """
        settings = get_settings()
        self.guacamole_url = guacamole_url or settings.GUACAMOLE_URL
        base_url = self.guacamole_url.rstrip("/")
        super().__init__(base_url=base_url)
        self.logger = logging.getLogger(self.__class__.__name__)

    def json_auth_login(self, data: str) -> str:
        """Login to Guacamole using JSON auth.

        Args:
            data: JSON auth data

        Returns:
            str: Authentication token

        Raises:
            APIError: If login fails
        """
        try:
            endpoint = f"{self.guacamole_url}/api/tokens"
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            response = requests.post(endpoint, headers=headers, data={"data": data}, timeout=self.timeout)
            response.raise_for_status()
            return response.json().get("authToken")
        except Exception as e:
            self.logger.error("Failed to login to Guacamole: %s", str(e))
            raise APIError(f"Failed to login to Guacamole: {e!s}", status_code=401) from e
