import base64
import os

from cryptography.fernet import Fernet


# Get encryption key from environment variable or use a default for development
# In production, always use an environment variable or secret management service
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")

if not ENCRYPTION_KEY:
    # For development only - in production, fail if no key is provided
    # Generate a valid Fernet key for development
    ENCRYPTION_KEY = Fernet.generate_key()
    print("WARNING: Using generated encryption key. In production, set ENCRYPTION_KEY environment variable.")

# Initialize Fernet cipher with the key
cipher = Fernet(ENCRYPTION_KEY if isinstance(ENCRYPTION_KEY, bytes) else ENCRYPTION_KEY.encode())


def encrypt_password(password: str) -> str:
    """Encrypt a password string.

    Args:
        password: The plaintext password to encrypt

    Returns:
        The encrypted password as a string
    """
    if not password:
        return None

    # Convert string to bytes, encrypt, and convert back to string
    encrypted_bytes = cipher.encrypt(password.encode())
    return base64.urlsafe_b64encode(encrypted_bytes).decode()


def decrypt_password(encrypted_password: str) -> str:
    """Decrypt an encrypted password.

    Args:
        encrypted_password: The encrypted password

    Returns:
        The decrypted plaintext password
    """
    if not encrypted_password:
        return None

    # Convert string to bytes, decrypt, and convert back to string
    encrypted_bytes = base64.urlsafe_b64decode(encrypted_password)
    return cipher.decrypt(encrypted_bytes).decode()


def generate_key() -> str:
    """Generate a new encryption key.

    This can be used to generate a key for production use.

    Returns:
        A new Fernet key as a string
    """
    return Fernet.generate_key().decode()
