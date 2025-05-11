import pytest
import sys
import os
from unittest.mock import patch, MagicMock
import base64
from cryptography.fernet import Fernet

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from utils.encryption import encrypt_password, decrypt_password, generate_key


@pytest.fixture
def fernet_key():
    """Generate a test Fernet key."""
    return Fernet.generate_key()


@pytest.fixture
def patch_cipher(fernet_key):
    """Patch the cipher with a test key."""
    with patch("utils.encryption.cipher") as mock_cipher:
        # Create a real Fernet instance for testing
        real_cipher = Fernet(fernet_key)

        # Make the mock behave like the real cipher
        mock_cipher.encrypt.side_effect = real_cipher.encrypt
        mock_cipher.decrypt.side_effect = real_cipher.decrypt

        yield mock_cipher


class TestEncryption:
    """Tests for encryption utility functions."""

    def test_encrypt_password(self, patch_cipher):
        """Test password encryption."""
        # Arrange
        password = "SecurePassword123!"

        # Act
        encrypted = encrypt_password(password)

        # Assert
        assert encrypted is not None
        assert encrypted != password
        assert isinstance(encrypted, str)

        # Verify the mock was called
        patch_cipher.encrypt.assert_called_once()

    def test_decrypt_password(self, patch_cipher, fernet_key):
        """Test password decryption."""
        # Arrange
        password = "SecurePassword123!"
        real_cipher = Fernet(fernet_key)
        encrypted_bytes = real_cipher.encrypt(password.encode())
        encrypted = base64.urlsafe_b64encode(encrypted_bytes).decode()

        # Act
        decrypted = decrypt_password(encrypted)

        # Assert
        assert decrypted == password

        # Verify the mock was called
        patch_cipher.decrypt.assert_called_once()

    def test_encrypt_decrypt_cycle(self, patch_cipher):
        """Test full encryption and decryption cycle."""
        # Arrange
        password = "VerySecurePassword456!"

        # Act
        encrypted = encrypt_password(password)
        decrypted = decrypt_password(encrypted)

        # Assert
        assert decrypted == password
        assert encrypted != password

        # Verify the mocks were called
        patch_cipher.encrypt.assert_called_once()
        patch_cipher.decrypt.assert_called_once()

    def test_encrypt_empty_password(self, patch_cipher):
        """Test encrypting an empty password."""
        # Act
        result = encrypt_password(None)

        # Assert
        assert result is None

        # Verify the mock was not called
        patch_cipher.encrypt.assert_not_called()

    def test_decrypt_empty_password(self, patch_cipher):
        """Test decrypting an empty password."""
        # Act
        result = decrypt_password(None)

        # Assert
        assert result is None

        # Verify the mock was not called
        patch_cipher.decrypt.assert_not_called()

    def test_generate_key(self):
        """Test key generation."""
        # Act
        key = generate_key()

        # Assert
        assert key is not None
        assert isinstance(key, str)

        # Test that the key is valid by creating a Fernet instance
        fernet = Fernet(key.encode())
        assert fernet is not None
