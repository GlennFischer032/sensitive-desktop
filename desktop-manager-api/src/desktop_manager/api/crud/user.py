from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from typing import Optional, List, Dict, Any
from desktop_manager.api.models.user import User
from desktop_manager.api.schemas.user import UserCreate, UserUpdate
from desktop_manager.core.security import get_password_hash
import logging

logger: logging.Logger = logging.getLogger(__name__)

def get_user(db: Session, user_id: int) -> Optional[User]:
    """Get a user by ID."""
    return db.query(User).filter(User.id == user_id).first()

def get_user_by_username(db: Session, username: str) -> Optional[User]:
    """Get a user by username."""
    return db.query(User).filter(User.username == username).first()

def get_users(db: Session, skip: int = 0, limit: int = 100) -> List[User]:
    """Get a list of users with pagination."""
    return db.query(User).offset(skip).limit(limit).all()

def create_user(db: Session, user: UserCreate) -> User:
    """Create a new user."""
    try:
        password_hash: str = get_password_hash(user.password)
        db_user = User(
            username=user.username,
            password_hash=password_hash,
            is_admin=user.is_admin
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
    except IntegrityError as e:
        db.rollback()
        logger.error(f"Failed to create user: {str(e)}")
        raise ValueError("Username already exists")
    except Exception as e:
        db.rollback()
        logger.error(f"Unexpected error creating user: {str(e)}")
        raise

def update_user(db: Session, user_id: int, user_update: UserUpdate) -> Optional[User]:
    """Update a user's information."""
    try:
        db_user = get_user(db, user_id)
        if not db_user:
            return None
            
        update_data: Dict[str, Any] = user_update.model_dump(exclude_unset=True)
        if "password" in update_data:
            update_data["password_hash"] = get_password_hash(update_data.pop("password"))
            
        for field, value in update_data.items():
            setattr(db_user, field, value)
            
        db.commit()
        db.refresh(db_user)
        return db_user
    except IntegrityError as e:
        db.rollback()
        logger.error(f"Failed to update user: {str(e)}")
        raise ValueError("Username already exists")
    except Exception as e:
        db.rollback()
        logger.error(f"Unexpected error updating user: {str(e)}")
        raise

def delete_user(db: Session, user_id: int) -> bool:
    """Delete a user."""
    try:
        db_user = get_user(db, user_id)
        if not db_user:
            return False
            
        db.delete(db_user)
        db.commit()
        return True
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to delete user: {str(e)}")
        raise 