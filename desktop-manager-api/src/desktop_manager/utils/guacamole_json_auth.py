"""Guacamole JSON Authentication Utility Module.

This module provides functionality to generate properly formatted, signed,
and encrypted JSON for Guacamole authentication according to the JSON auth
extension specification from Apache Guacamole.
"""

import base64
import hashlib
import hmac
import json
import time
from typing import Any

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from desktop_manager.config.settings import get_settings


class GuacamoleJsonAuth:
    """Utility class for generating Guacamole JSON authentication tokens."""

    def __init__(self, secret_key: str | None = None, guacamole_url: str | None = None):
        """Initialize the GuacamoleJsonAuth utility.

        Args:
            secret_key: The secret key to use for signing and encrypting the JSON.
                        If not provided, it will be retrieved from settings.
            guacamole_url: The base URL of the Guacamole server.
                          If not provided, it will be retrieved from settings.
        """
        self.settings = get_settings()
        self.secret_key = secret_key or self.settings.GUACAMOLE_JSON_SECRET_KEY
        self.guacamole_url = guacamole_url or self.settings.GUACAMOLE_URL

        if not self.secret_key:
            raise ValueError("No JSON secret key provided or found in settings")

        # Convert hex key string to bytes
        try:
            # If key is a hex string of the correct length, decode it directly
            is_valid_hex = all(c in "0123456789abcdefABCDEF" for c in self.secret_key)
            if len(self.secret_key) == 32 and is_valid_hex:
                self.key_bytes = bytes.fromhex(self.secret_key)
            # For any other string, generate MD5 hash
            else:
                self.key_bytes = hashlib.md5(self.secret_key.encode()).digest()  # noqa: S324
        except ValueError as e:
            raise ValueError(f"Invalid hex value in secret key: {e}") from e

    def generate_auth_data(
        self,
        username: str,
        connections: dict[str, dict[str, Any]],
        expires_in_ms: int = 3600000,  # Default: 1 hour in milliseconds
    ) -> str:
        """Generate an encrypted and signed JSON auth token for Guacamole.

        Args:
            username: The username to authenticate
            connections: Dictionary of connections accessible to the user
            expires_in_ms: Token expiration time in milliseconds from now

        Returns:
            Base64-encoded, encrypted, and signed JSON authentication data
        """
        # Create authentication data
        auth_data = {
            "username": username,
            "expires": int(time.time() * 1000) + expires_in_ms,
            "connections": connections,
        }

        # Convert to JSON
        json_data = json.dumps(auth_data).encode("utf-8")

        # Sign the data with HMAC-SHA256
        signature = hmac.new(self.key_bytes, json_data, hashlib.sha256).digest()

        # Concatenate signature and JSON
        signed_data = signature + json_data

        # Encrypt with AES-CBC (IV of all zeros as specified in Guacamole docs)
        iv = b"\0" * 16  # 16 bytes of zeros
        cipher = AES.new(self.key_bytes, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(signed_data, AES.block_size))

        # Base64 encode
        return base64.b64encode(encrypted_data).decode("utf-8")
