from datetime import datetime, timedelta
import logging
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

from desktop_manager.config.settings import get_settings


logger: logging.Logger = logging.getLogger(__name__)
settings = get_settings()

# Enhanced password hashing configuration
pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],
    deprecated="auto",
    argon2__rounds=4,
    argon2__memory_cost=65536,
    argon2__parallelism=2,
    bcrypt__rounds=12,
)


class TokenData(BaseModel):
    """Schema for JWT token data."""

    user_id: int = Field(..., description="User ID")
    username: str = Field(..., description="Username")
    is_admin: bool = Field(..., description="Admin status")
    exp: datetime = Field(..., description="Expiration timestamp")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash.

    Args:
        plain_password: The password to verify
        hashed_password: The hash to verify against

    Returns:
        bool: True if password matches, False otherwise
    """
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error("Password verification error: %s", str(e))
        return False


def get_password_hash(password: str) -> str:
    """Generate a password hash using the configured algorithm.

    Args:
        password: The password to hash

    Returns:
        str: The hashed password
    """
    try:
        return pwd_context.hash(password)
    except Exception as e:
        logger.error("Password hashing error: %s", str(e))
        raise ValueError("Failed to hash password") from e


def create_access_token(data: dict[str, Any], expires_delta: timedelta | None = None) -> str:
    """Create a JWT access token.

    Args:
        data: The data to encode in the token
        expires_delta: Optional expiration time delta

    Returns:
        str: The encoded JWT token

    Raises:
        ValueError: If token creation fails
    """
    try:
        to_encode = data.copy()
        expire = datetime.utcnow() + (expires_delta or timedelta(minutes=30))
        to_encode.update({"exp": expire})

        # Validate token data
        TokenData(**to_encode)

        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
        return encoded_jwt
    except Exception as e:
        logger.error("Failed to create access token: %s", str(e))
        raise ValueError("Failed to create access token") from e


def decode_token(token: str) -> dict[str, Any]:
    """Decode and verify a JWT token.

    Args:
        token: The token to decode

    Returns:
        Dict[str, Any]: The decoded token data

    Raises:
        JWTError: If token is invalid or expired
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        # Validate token data
        TokenData(**payload)
        return payload
    except JWTError as e:
        logger.error("Failed to decode token: %s", str(e))
        raise
    except Exception as e:
        logger.error("Unexpected error decoding token: %s", str(e))
        raise


def hash_migrate(old_hash: str) -> str | None:
    """Migrate an old password hash to the current hashing scheme if needed.

    Args:
        old_hash: The old password hash

    Returns:
        Optional[str]: New hash if migration was needed, None otherwise
    """
    if pwd_context.needs_update(old_hash):
        try:
            # Get the password that created this hash
            password = pwd_context.identify_verify(old_hash)
            if password:
                return get_password_hash(password)
        except Exception as e:
            logger.error("Hash migration error: %s", str(e))
    return None
