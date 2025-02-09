from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from typing import Optional, List, Dict, Any
from desktop_manager.api.models.desktop import Desktop
from desktop_manager.api.schemas.desktop import DesktopCreate, DesktopUpdate
import logging

logger: logging.Logger = logging.getLogger(__name__)

def get_desktop(db: Session, desktop_id: int) -> Optional[Desktop]:
    """Get a desktop by ID."""
    return db.query(Desktop).filter(Desktop.id == desktop_id).first()

def get_desktop_by_connection_id(db: Session, connection_id: str) -> Optional[Desktop]:
    """Get a desktop by connection ID."""
    return db.query(Desktop).filter(Desktop.connection_id == connection_id).first()

def get_desktops(
    db: Session,
    user_id: Optional[int] = None,
    skip: int = 0,
    limit: int = 100
) -> List[Desktop]:
    """Get a list of desktops with optional user filter and pagination."""
    query = db.query(Desktop)
    if user_id is not None:
        query = query.filter(Desktop.user_id == user_id)
    return query.offset(skip).limit(limit).all()

def create_desktop(
    db: Session,
    desktop: DesktopCreate,
    user_id: int,
    connection_id: str,
    ip_address: Optional[str],
    vnc_password: str
) -> Desktop:
    """Create a new desktop."""
    try:
        db_desktop = Desktop(
            name=desktop.name,
            user_id=user_id,
            connection_id=connection_id,
            ip_address=ip_address,
            vnc_password=vnc_password
        )
        db.add(db_desktop)
        db.commit()
        db.refresh(db_desktop)
        return db_desktop
    except IntegrityError as e:
        db.rollback()
        logger.error(f"Failed to create desktop: {str(e)}")
        raise ValueError("Connection ID already exists")
    except Exception as e:
        db.rollback()
        logger.error(f"Unexpected error creating desktop: {str(e)}")
        raise

def update_desktop(
    db: Session,
    desktop_id: int,
    desktop_update: DesktopUpdate
) -> Optional[Desktop]:
    """Update a desktop's information."""
    try:
        db_desktop = get_desktop(db, desktop_id)
        if not db_desktop:
            return None
            
        update_data: Dict[str, Any] = desktop_update.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(db_desktop, field, value)
            
        db.commit()
        db.refresh(db_desktop)
        return db_desktop
    except IntegrityError as e:
        db.rollback()
        logger.error(f"Failed to update desktop: {str(e)}")
        raise ValueError("Connection ID already exists")
    except Exception as e:
        db.rollback()
        logger.error(f"Unexpected error updating desktop: {str(e)}")
        raise

def delete_desktop(db: Session, desktop_id: int) -> bool:
    """Delete a desktop."""
    try:
        db_desktop = get_desktop(db, desktop_id)
        if not db_desktop:
            return False
            
        db.delete(db_desktop)
        db.commit()
        return True
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to delete desktop: {str(e)}")
        raise 