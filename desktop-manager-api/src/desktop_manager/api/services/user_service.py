import logging
from typing import List, Optional

from sqlalchemy.orm import Session

from desktop_manager.api.models.user import User
from desktop_manager.api.schemas.user import UserCreate, UserResponse
from desktop_manager.clients.guacamole import GuacamoleClient
from desktop_manager.core.exceptions import (
    DatabaseError,
    GuacamoleError,
    UserAlreadyExistsError,
    UserNotFoundError,
)


logger = logging.getLogger(__name__)


class UserService:
    """Service class for handling user-related operations.

    This class implements the business logic for user management, including
    creation, deletion, and retrieval of users. It handles both the application
    database and Guacamole user management.

    Attributes:
        db (Session): SQLAlchemy database session
        guacamole_client (GuacamoleClient): Client for Guacamole operations
    """

    def __init__(self, db: Session, guacamole_client: GuacamoleClient):
        """Initialize the UserService.

        Args:
            db: SQLAlchemy database session
            guacamole_client: Client for Guacamole operations
        """
        self.db = db
        self.guacamole_client = guacamole_client

    def create_user(self, user_data: UserCreate) -> UserResponse:
        """Create a new user in both the application database and Guacamole.

        Args:
            user_data: Validated user creation data

        Returns:
            Created user data

        Raises:
            UserAlreadyExistsError: If user with given username already exists
            GuacamoleError: If Guacamole operations fail
            DatabaseError: If database operations fail
        """
        logger.info("Creating new user with username: %s", user_data.username)

        # Check if user exists
        if self._get_user_by_username(user_data.username):
            logger.error("User %s already exists", user_data.username)
            raise UserAlreadyExistsError(f"User {user_data.username} already exists")

        try:
            # Create user in Guacamole
            self.guacamole_client.login()

            # Create empty-password user in Guacamole for JSON auth
            self.guacamole_client.create_user_if_not_exists(
                token=None,
                username=user_data.username,
                password="",  # Empty password for JSON auth
                attributes={
                    "guac_full_name": user_data.username,
                    "guac_organization": user_data.organization or "Default",
                },
            )
            logger.info("Created user %s in Guacamole", user_data.username)

            # Create user in database
            user = User(
                username=user_data.username,
                email=user_data.email,
                organization=user_data.organization,
                is_admin=user_data.is_admin,
                sub=user_data.sub,
            )
            self.db.add(user)
            self.db.commit()
            self.db.refresh(user)
            logger.info("Created user %s in database", user_data.username)

            return UserResponse(
                id=user.id,
                username=user.username,
                email=user.email,
                organization=user.organization,
                is_admin=user.is_admin,
                created_at=user.created_at,
            )

        except Exception as e:
            logger.error("Failed to create user %s: %s", user_data.username, str(e))
            self.db.rollback()
            # Cleanup Guacamole user if database fails
            try:
                self.guacamole_client.delete_user(user_data.username)
            except Exception as cleanup_error:
                logger.error("Failed to cleanup Guacamole user: %s", cleanup_error)
            raise DatabaseError(f"Failed to create user: {e!s}") from e

    def delete_user(self, username: str) -> None:
        """Delete a user from both the application database and Guacamole.
        If the user doesn't exist in Guacamole but exists in the database,
        we consider this an inconsistency and proceed with database deletion.

        Args:
            username: Username of the user to delete

        Raises:
            UserNotFoundError: If user does not exist in the database
            GuacamoleError: If there's a network or other error communicating with Guacamole
            DatabaseError: If database operations fail
        """
        logger.info("Deleting user: %s", username)

        user = self._get_user_by_username(username)
        if not user:
            logger.error("User %s not found", username)
            raise UserNotFoundError(f"User {username} not found")

        try:
            # Try to delete from Guacamole first
            try:
                self.guacamole_client.delete_user(username)
                logger.info("Deleted user %s from Guacamole", username)
            except GuacamoleError as e:
                if "User not found" in str(e):
                    # User not found in Guacamole is ok - we'll clean up the database
                    logger.warning(
                        "User %s not found in Guacamole, proceeding with database cleanup",
                        username,
                    )
                else:
                    # Other Guacamole errors (network, etc.) should prevent deletion
                    logger.error("Failed to communicate with Guacamole: %s", str(e))
                    raise

            # Delete from database
            self.db.delete(user)
            try:
                self.db.commit()
                logger.info("Deleted user %s from database", username)
            except Exception as e:
                self.db.rollback()
                raise DatabaseError(f"Failed to delete user from database: {e!s}") from e

        except GuacamoleError:
            # Re-raise Guacamole communication errors
            raise
        except Exception as e:
            logger.error("Failed to delete user %s: %s", username, str(e))
            raise DatabaseError(f"Failed to delete user: {e!s}") from e

    def get_users(self) -> List[UserResponse]:
        """Get all users from the database.

        Returns:
            List of user data

        Raises:
            DatabaseError: If database operations fail
        """
        try:
            users = self.db.query(User).all()
            return [
                UserResponse(
                    id=user.id,
                    username=user.username,
                    email=user.email,
                    organization=user.organization,
                    is_admin=user.is_admin,
                    created_at=user.created_at,
                )
                for user in users
            ]
        except Exception as e:
            logger.error("Failed to get users: %s", str(e))
            raise DatabaseError(f"Failed to get users: {e!s}") from e

    def _get_user_by_username(self, username: str) -> Optional[User]:
        """Get a user by username.

        Args:
            username: Username to look up

        Returns:
            User if found, None otherwise
        """
        return self.db.query(User).filter(User.username == username).first()
