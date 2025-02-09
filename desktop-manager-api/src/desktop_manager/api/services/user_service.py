from typing import List, Optional
from sqlalchemy.orm import Session
from werkzeug.security import generate_password_hash

from desktop_manager.api.models.user import User
from desktop_manager.api.schemas.user import UserCreate, UserResponse
from desktop_manager.core.guacamole import (
    GuacamoleClient,
    create_guacamole_user,
    ensure_all_users_group,
    add_user_to_group,
    delete_guacamole_user
)
from desktop_manager.core.exceptions import (
    UserAlreadyExistsError,
    UserNotFoundError,
    GuacamoleError,
    DatabaseError
)
import logging

logger = logging.getLogger(__name__)

class UserService:
    """
    Service class for handling user-related operations.
    
    This class implements the business logic for user management, including
    creation, deletion, and retrieval of users. It handles both the application
    database and Guacamole user management.
    
    Attributes:
        db (Session): SQLAlchemy database session
        guacamole_client (GuacamoleClient): Client for Guacamole operations
    """
    
    def __init__(self, db: Session, guacamole_client: GuacamoleClient):
        """
        Initialize the UserService.
        
        Args:
            db: SQLAlchemy database session
            guacamole_client: Client for Guacamole operations
        """
        self.db = db
        self.guacamole_client = guacamole_client
    
    def create_user(self, user_data: UserCreate) -> UserResponse:
        """
        Create a new user in both the application database and Guacamole.
        
        Args:
            user_data: Validated user creation data
            
        Returns:
            Created user data
            
        Raises:
            UserAlreadyExistsError: If user with given username already exists
            GuacamoleError: If Guacamole operations fail
            DatabaseError: If database operations fail
        """
        logger.info(f"Creating new user with username: {user_data.username}")
        
        # Check if user exists
        if self._get_user_by_username(user_data.username):
            logger.error(f"User {user_data.username} already exists")
            raise UserAlreadyExistsError(f"User {user_data.username} already exists")
            
        try:
            # Create user in Guacamole
            token = self.guacamole_client.login()
            create_guacamole_user(token, user_data.username, user_data.password)
            ensure_all_users_group(token)
            add_user_to_group(token, user_data.username, 'all_users')
            logger.info(f"Created user {user_data.username} in Guacamole")
            
            # Create user in database
            user = User(
                username=user_data.username,
                password_hash=generate_password_hash(user_data.password),
                is_admin=user_data.is_admin
            )
            self.db.add(user)
            self.db.commit()
            self.db.refresh(user)
            logger.info(f"Created user {user_data.username} in database")
            
            return UserResponse(
                id=user.id,
                username=user.username,
                is_admin=user.is_admin,
                created_at=user.created_at
            )
            
        except Exception as e:
            logger.error(f"Failed to create user {user_data.username}: {str(e)}")
            self.db.rollback()
            # Cleanup Guacamole user if database fails
            try:
                delete_guacamole_user(token, user_data.username)
            except Exception as cleanup_error:
                logger.error(f"Failed to cleanup Guacamole user: {cleanup_error}")
            raise DatabaseError(f"Failed to create user: {str(e)}")
    
    def delete_user(self, username: str) -> None:
        """
        Delete a user from both the application database and Guacamole.
        
        Args:
            username: Username of the user to delete
            
        Raises:
            UserNotFoundError: If user does not exist
            GuacamoleError: If Guacamole operations fail
            DatabaseError: If database operations fail
        """
        logger.info(f"Deleting user: {username}")
        
        user = self._get_user_by_username(username)
        if not user:
            logger.error(f"User {username} not found")
            raise UserNotFoundError(f"User {username} not found")
            
        try:
            # Delete from Guacamole
            token = self.guacamole_client.login()
            delete_guacamole_user(token, username)
            logger.info(f"Deleted user {username} from Guacamole")
            
            # Delete from database
            self.db.delete(user)
            self.db.commit()
            logger.info(f"Deleted user {username} from database")
            
        except Exception as e:
            logger.error(f"Failed to delete user {username}: {str(e)}")
            self.db.rollback()
            raise DatabaseError(f"Failed to delete user: {str(e)}")
    
    def get_users(self) -> List[UserResponse]:
        """
        Get all users from the database.
        
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
                    is_admin=user.is_admin,
                    created_at=user.created_at
                )
                for user in users
            ]
        except Exception as e:
            logger.error(f"Failed to get users: {str(e)}")
            raise DatabaseError(f"Failed to get users: {str(e)}")
    
    def _get_user_by_username(self, username: str) -> Optional[User]:
        """
        Get a user by username.
        
        Args:
            username: Username to look up
            
        Returns:
            User if found, None otherwise
        """
        return self.db.query(User).filter(User.username == username).first() 