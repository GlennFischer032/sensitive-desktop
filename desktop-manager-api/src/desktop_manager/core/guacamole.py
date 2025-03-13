"""Guacamole core module for desktop-manager-api.

This module provides type definitions for Apache Guacamole.
"""

import logging
from typing import Any, Dict, List, Literal, NotRequired, Optional, TypedDict, Union

from desktop_manager.config.settings import get_settings


logger = logging.getLogger(__name__)


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
    timezone: Optional[str]


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
    enable_audio: str
    read_only: NotRequired[str]
    swap_red_blue: NotRequired[str]
    cursor: NotRequired[str]
    color_depth: NotRequired[str]
    force_lossless: NotRequired[str]
    clipboard_encoding: NotRequired[str]
    disable_copy: NotRequired[str]
    disable_paste: NotRequired[str]
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


class GuacamoleConnection(TypedDict):
    """Type definition for Guacamole connection."""

    name: str
    identifier: str
    parentIdentifier: str
    protocol: Literal["vnc"]
    attributes: GuacamoleConnectionAttributes
    activeConnections: int
    lastActive: int
    parameters: GuacamoleConnectionParameters


class GuacamolePatchOperation(TypedDict):
    """Type definition for Guacamole PATCH operation."""

    op: Literal["add", "remove"]
    path: str
    value: Union[str, None]


class GuacamoleAuthResponse(TypedDict):
    """Type definition for Guacamole authentication response."""

    authToken: str


class GuacamoleConnectionResponse(TypedDict):
    """Type definition for Guacamole connection response."""

    identifier: str


class GuacamoleUsersResponse(TypedDict):
    """Type definition for Guacamole users response."""

    username: str
    lastActive: int
    attributes: GuacamoleUserAttributes
