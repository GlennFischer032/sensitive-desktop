"""Guacamole client module for desktop-manager-api.

This module provides a client for interacting with Apache Guacamole.
"""

import logging
from typing import NotRequired, TypedDict

from clients.base import APIError, BaseClient
from config.settings import get_settings
import requests


class GuacamoleUserAttributes(TypedDict, total=False):
    """Type definition for Guacamole user attributes."""

    guac_full_name: str
    guac_organization: str
    expired: str
    disabled: str
    access_window_start: str
    access_window_end: str
    valid_from: str
    valid_until: str
    timezone: str | None


class GuacamoleUser(TypedDict):
    """Type definition for Guacamole user."""

    username: str
    password: str
    attributes: GuacamoleUserAttributes


class GuacamoleGroup(TypedDict):
    """Type definition for Guacamole group."""

    identifier: str
    attributes: GuacamoleUserAttributes


class GuacamoleConnectionParameters(TypedDict):
    """Type definition for Guacamole connection parameters."""

    hostname: str
    port: str
    password: str
    enable_audio: NotRequired[str] = "true"
    read_only: NotRequired[str]
    swap_red_blue: NotRequired[str]
    cursor: NotRequired[str]
    color_depth: NotRequired[str]
    force_lossless: NotRequired[str]
    clipboard_encoding: NotRequired[str]
    disable_copy: NotRequired[str] = "true"
    disable_paste: NotRequired[str] = "false"
    dest_port: NotRequired[str]
    recording_exclude_output: NotRequired[str]
    recording_exclude_mouse: NotRequired[str]
    recording_include_keys: NotRequired[str]
    create_recording_path: NotRequired[str]
    enable_sftp: NotRequired[str]
    sftp_port: NotRequired[str]
    sftp_server_alive_interval: NotRequired[str]
    sftp_disable_download: NotRequired[str]
    sftp_disable_upload: NotRequired[str]
    wol_send_packet: NotRequired[str]
    wol_udp_port: NotRequired[str]
    wol_wait_time: NotRequired[str]


class GuacamoleConnectionAttributes(TypedDict, total=False):
    """Type definition for Guacamole connection attributes."""

    max_connections: str
    max_connections_per_user: str
    weight: str
    failover_only: str
    guacd_hostname: str
    guacd_port: str
    guacd_encryption: str


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
