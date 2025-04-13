"""SQLAlchemy model for tokens.

This module defines the Token model for database operations.
"""

from datetime import datetime

from schemas.base import Base
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.sql import func


class Token(Base):
    """SQLAlchemy model for API tokens.

    This model stores information about API tokens used for admin authentication.

    Attributes:
        id (int): Primary key, auto-incrementing identifier
        token_id (str): Unique token identifier (UUID)
        name (str): Name of the token
        description (str): Optional description for the token
        created_at (datetime): When the token was created
        expires_at (datetime): When the token expires
        created_by (str): Username of the token creator
        last_used (datetime): When the token was last used
        revoked (bool): Whether the token has been revoked
        revoked_at (datetime): When the token was revoked
    """

    __tablename__ = "tokens"

    id: int = Column(Integer, primary_key=True)
    token_id: str = Column(String(36), unique=True, nullable=False, index=True)
    name: str = Column(String(255), nullable=False)
    description: str = Column(Text, nullable=True)
    created_at: datetime = Column(DateTime, server_default=func.now(), nullable=False)
    expires_at: datetime = Column(DateTime, nullable=False)
    created_by: str = Column(String(255), ForeignKey("users.username", ondelete="CASCADE"), nullable=False)
    last_used: datetime = Column(DateTime, nullable=True)
    revoked: bool = Column(Boolean, default=False, nullable=False)
    revoked_at: datetime = Column(DateTime, nullable=True)

    def __repr__(self) -> str:
        """Return string representation of the Token."""
        return f"<Token {self.name} ({self.token_id})>"
