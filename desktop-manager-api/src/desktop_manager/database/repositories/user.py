"""User repository module.

This module provides a repository for user operations.
"""

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from desktop_manager.database.models.user import PKCEState, SocialAuthAssociation, User
from desktop_manager.database.repositories.base import BaseRepository


class UserRepository(BaseRepository[User]):
    """Repository for user operations.

    This class provides methods for user-specific operations such as creating,
    updating, and retrieving users, as well as managing OIDC associations.
    """

    def __init__(self, session: Session):
        """Initialize the repository with a session.

        Args:
            session: SQLAlchemy session for database operations
        """
        super().__init__(session, User)

    def get_by_username(self, username: str) -> User | None:
        """Get a user by username.

        Args:
            username: Username

        Returns:
            User if found, None otherwise
        """
        return self.session.query(User).filter(User.username == username).first()

    def get_by_sub(self, sub: str) -> User | None:
        """Get a user by OIDC subject identifier.

        Args:
            sub: OIDC subject identifier

        Returns:
            User if found, None otherwise
        """
        return self.session.query(User).filter(User.sub == sub).first()

    def get_by_email(self, email: str) -> User | None:
        """Get a user by email.

        Args:
            email: Email address

        Returns:
            User if found, None otherwise
        """
        return self.session.query(User).filter(User.email == email).first()

    def create_user(self, data: dict[str, Any]) -> User:
        """Create a new user.

        Args:
            data: User data

        Returns:
            Newly created user
        """
        user = User(
            username=data["username"],
            email=data.get("email"),
            is_admin=data.get("is_admin", False),
            sub=data.get("sub"),
            given_name=data.get("given_name"),
            family_name=data.get("family_name"),
            name=data.get("name"),
            organization=data.get("organization"),
            locale=data.get("locale"),
            email_verified=data.get("email_verified", False),
        )
        return self.create(user)

    def update_user(self, user_id: int, data: dict[str, Any]) -> User | None:
        """Update a user.

        Args:
            user_id: User ID
            data: Updated user data

        Returns:
            Updated user if found, None otherwise
        """
        user = self.session.query(User).filter(User.id == user_id).first()
        if user:
            if "email" in data:
                user.email = data["email"]
            if "is_admin" in data:
                user.is_admin = data["is_admin"]
            if "organization" in data:
                user.organization = data["organization"]
            if "locale" in data:
                user.locale = data["locale"]
            if "name" in data:
                user.name = data["name"]
            if "given_name" in data:
                user.given_name = data["given_name"]
            if "family_name" in data:
                user.family_name = data["family_name"]
            if "email_verified" in data:
                user.email_verified = data["email_verified"]

            self.update(user)
        return user

    def update_last_login(self, user_id: int) -> User | None:
        """Update a user's last login timestamp.

        Args:
            user_id: User ID

        Returns:
            Updated user if found, None otherwise
        """
        user = self.session.query(User).filter(User.id == user_id).first()
        if user:
            user.last_login = datetime.utcnow()
            self.update(user)
        return user

    def delete_user(self, user_id: int) -> bool:
        """Delete a user.

        Args:
            user_id: User ID

        Returns:
            True if user was deleted, False otherwise
        """
        user = self.session.query(User).filter(User.id == user_id).first()
        if user:
            self.session.delete(user)
            self.session.commit()
            return True
        return False

    def get_all_users(self) -> list[User]:
        """Get all users.

        Returns:
            List of all users
        """
        return self.session.query(User).order_by(User.username).all()

    # Social auth association methods
    def create_social_auth(self, user_id: int, data: dict[str, Any]) -> SocialAuthAssociation:
        """Create a social auth association.

        Args:
            user_id: User ID
            data: Social auth data

        Returns:
            Created social auth association
        """
        social_auth = SocialAuthAssociation(
            user_id=user_id,
            provider=data["provider"],
            provider_user_id=data["provider_user_id"],
            provider_name=data.get("provider_name"),
            extra_data=data.get("extra_data"),
        )
        self.session.add(social_auth)
        self.session.commit()
        return social_auth

    def get_social_auth(self, provider: str, provider_user_id: str) -> SocialAuthAssociation | None:
        """Get a social auth association.

        Args:
            provider: Auth provider
            provider_user_id: User ID from the provider

        Returns:
            Social auth association if found, None otherwise
        """
        return (
            self.session.query(SocialAuthAssociation)
            .filter(
                SocialAuthAssociation.provider == provider,
                SocialAuthAssociation.provider_user_id == provider_user_id,
            )
            .first()
        )

    def update_social_auth_last_used(self, social_auth_id: int) -> SocialAuthAssociation | None:
        """Update a social auth association's last used timestamp.

        Args:
            social_auth_id: Social auth association ID

        Returns:
            Updated social auth association if found, None otherwise
        """
        social_auth = (
            self.session.query(SocialAuthAssociation).filter(SocialAuthAssociation.id == social_auth_id).first()
        )
        if social_auth:
            social_auth.last_used = datetime.utcnow()
            self.session.commit()
        return social_auth

    # PKCE state methods
    def create_pkce_state(self, state: str, code_verifier: str, expires_at: datetime) -> PKCEState:
        """Create a PKCE state.

        Args:
            state: State string
            code_verifier: Code verifier
            expires_at: Expiration timestamp

        Returns:
            Created PKCE state
        """
        pkce_state = PKCEState(
            state=state,
            code_verifier=code_verifier,
            expires_at=expires_at,
        )
        self.session.add(pkce_state)
        self.session.commit()
        return pkce_state

    def get_pkce_state(self, state: str) -> PKCEState | None:
        """Get a PKCE state.

        Args:
            state: State string

        Returns:
            PKCE state if found, None otherwise
        """
        return self.session.query(PKCEState).filter(PKCEState.state == state, PKCEState.used is False).first()

    def mark_pkce_state_used(self, state_id: int) -> PKCEState | None:
        """Mark a PKCE state as used.

        Args:
            state_id: State ID

        Returns:
            Updated PKCE state if found, None otherwise
        """
        pkce_state = self.session.query(PKCEState).filter(PKCEState.id == state_id).first()
        if pkce_state:
            pkce_state.used = True
            self.session.commit()
        return pkce_state
