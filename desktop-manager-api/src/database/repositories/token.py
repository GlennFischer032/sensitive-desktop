"""Token repository module.

This module provides a repository for token operations.
"""

from datetime import datetime, timedelta
import uuid

from database.models.token import Token
from database.repositories.base import BaseRepository
from sqlalchemy import and_
from sqlalchemy.orm import Session


class TokenRepository(BaseRepository[Token]):
    """Repository for token operations.

    This class provides methods for token-specific operations such as creating tokens,
    finding tokens by token_id, and managing token revocation.
    """

    def __init__(self, session: Session):
        """Initialize the repository with a session.

        Args:
            session: SQLAlchemy session for database operations
        """
        super().__init__(session, Token)

    def get_by_token_id(self, token_id: str) -> Token | None:
        """Get a token by its token_id.

        Args:
            token_id: Token identifier

        Returns:
            Token if found, None otherwise
        """
        return self.session.query(Token).filter(Token.token_id == token_id).first()

    def create_token(self, name: str, description: str | None, expires_in_days: int, created_by: str) -> Token:
        """Create a new token.

        Args:
            name: Token name
            description: Optional token description
            expires_in_days: Number of days until token expiration
            created_by: Username of token creator

        Returns:
            Newly created token
        """
        # Generate a unique token_id (UUID)
        token_id = str(uuid.uuid4())

        # Calculate expiration date
        expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

        # Create token entity
        token = Token(
            token_id=token_id, name=name, description=description, expires_at=expires_at, created_by=created_by
        )

        # Save to database
        return self.create(token)

    def revoke_token(self, token_id: str) -> Token | None:
        """Revoke a token.

        Args:
            token_id: Token identifier

        Returns:
            Updated token if found, None otherwise
        """
        token = self.get_by_token_id(token_id)
        if token:
            token.revoked = True
            token.revoked_at = datetime.utcnow()
            self.update(token)
        return token

    def update_last_used(self, token_id: str) -> Token | None:
        """Update the last_used timestamp for a token.

        Args:
            token_id: Token identifier

        Returns:
            Updated token if found, None otherwise
        """
        token = self.get_by_token_id(token_id)
        if token:
            token.last_used = datetime.utcnow()
            self.update(token)
        return token

    def get_valid_tokens(self, created_by: str | None = None) -> list[Token]:
        """Get all valid (non-expired, non-revoked) tokens.

        Args:
            created_by: Optional filter by creator username

        Returns:
            List of valid tokens
        """
        query = self.session.query(Token).filter(and_(Token.expires_at > datetime.utcnow(), Token.revoked is False))

        if created_by:
            query = query.filter(Token.created_by == created_by)

        return query.order_by(Token.created_at.desc()).all()

    def get_tokens_for_user(self, username: str) -> list[Token]:
        """Get all tokens for a specific user.

        Args:
            username: Username of token creator

        Returns:
            List of tokens
        """
        return self.session.query(Token).filter(Token.created_by == username).order_by(Token.created_at.desc()).all()

    def is_token_valid(self, token_id: str) -> bool:
        """Check if a token is valid (exists, not expired, not revoked).

        Args:
            token_id: Token identifier

        Returns:
            True if token is valid, False otherwise
        """
        token = self.get_by_token_id(token_id)
        if not token:
            return False

        return not token.revoked and token.expires_at > datetime.utcnow()
