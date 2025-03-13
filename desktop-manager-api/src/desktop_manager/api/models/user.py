from datetime import datetime

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from desktop_manager.api.models.base import Base


class SocialAuthAssociation(Base):
    """SQLAlchemy model for social auth associations.

    This model stores the relationship between users and their social auth providers,
    specifically for OIDC in our case.

    Attributes:
        id (int): Primary key
        user_id (int): Foreign key to users table
        provider (str): Auth provider (e.g., 'oidc')
        provider_user_id (str): User ID from the provider (sub in OIDC)
        provider_name (str): Name of the provider (e.g., 'e-infra')
        created_at (datetime): When the association was created
        last_used (datetime): Last time this association was used
        extra_data (dict): Additional data from the provider
    """

    __tablename__ = "social_auth_association"

    id: int = Column(Integer, primary_key=True)
    user_id: int = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    provider: str = Column(String(32), nullable=False)
    provider_user_id: str = Column(String(255), nullable=False)
    provider_name: str = Column(String(255))
    created_at: datetime = Column(DateTime, server_default=func.now())
    last_used: datetime = Column(DateTime, nullable=True)
    extra_data: dict = Column(JSON, nullable=True)

    # Relationship to user
    user = relationship("User", back_populates="social_auth")

    __table_args__ = {"mysql_charset": "utf8mb4", "mysql_collate": "utf8mb4_unicode_ci"}


class PKCEState(Base):
    """SQLAlchemy model for PKCE state management.

    This model stores PKCE state and code verifier pairs for OIDC authentication.

    Attributes:
        id (int): Primary key
        state (str): Random state string
        code_verifier (str): PKCE code verifier
        created_at (datetime): When the state was created
        expires_at (datetime): When the state expires
        used (bool): Whether this state has been used
    """

    __tablename__ = "pkce_state"

    id: int = Column(Integer, primary_key=True)
    state: str = Column(String(64), unique=True, nullable=False)
    code_verifier: str = Column(String(128), nullable=False)
    created_at: datetime = Column(DateTime, server_default=func.now())
    expires_at: datetime = Column(DateTime, nullable=True)
    used: bool = Column(Boolean, default=False)

    __table_args__ = {"mysql_charset": "utf8mb4", "mysql_collate": "utf8mb4_unicode_ci"}


class User(Base):
    """SQLAlchemy model representing a user in the system.

    This model stores information about users, including their authentication
    credentials, admin status, and creation timestamp. It also maintains
    relationships with their created connections and OIDC information.

    Attributes:
        id (int): Primary key, auto-incrementing identifier
        username (str): Unique username for the user
        email (str): Unique email address for the user
        organization (str): User's organization
        password_hash (str): Hashed password for authentication (optional for OIDC users)
        is_admin (bool): Whether the user has administrator privileges
        created_at (datetime): Timestamp of when the user was created
        sub (str): OIDC subject identifier
        given_name (str): User's given name from OIDC
        family_name (str): User's family name from OIDC
        locale (str): User's locale preference
        email_verified (bool): Whether email has been verified by OIDC provider
        last_login (datetime): Last login timestamp
        connections (List[Connection]): List of connections created by this user
        social_auth (List[SocialAuthAssociation]): Social auth associations
    """

    __tablename__: str = "users"

    id: int = Column(Integer, primary_key=True, index=True)
    username: str = Column(String(255), unique=True, index=True, nullable=False)
    email: str = Column(String(255), unique=True, index=True, nullable=False)
    organization: str = Column(String(255), nullable=True)
    password_hash: str = Column(String(255), nullable=True)
    is_admin: bool = Column(Boolean, default=False)
    created_at: datetime = Column(DateTime, server_default=func.now())

    # OIDC fields
    sub: str = Column(String(255), unique=True, nullable=True)
    given_name: str = Column(String(255), nullable=True)
    family_name: str = Column(String(255), nullable=True)
    locale: str = Column(String(10), nullable=True)
    email_verified: bool = Column(Boolean, default=False)
    last_login: datetime = Column(DateTime, nullable=True)

    # Relationships
    connections = relationship("Connection", back_populates="creator", cascade="all, delete-orphan")
    social_auth = relationship(
        "SocialAuthAssociation", back_populates="user", cascade="all, delete-orphan"
    )

    __table_args__ = {"mysql_charset": "utf8mb4", "mysql_collate": "utf8mb4_unicode_ci"}

    def __repr__(self) -> str:
        """Return string representation of the User."""
        return f"<User {self.username}>"

    @property
    def is_oidc_user(self) -> bool:
        """Check if user was created via OIDC."""
        return bool(self.sub)
