"""Session management module.

This module provides functions for managing database sessions.
"""

from collections.abc import Generator
from contextlib import contextmanager
import logging

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from desktop_manager.api.models.base import Base
from desktop_manager.config.settings import get_settings


logger = logging.getLogger(__name__)

# Global engine to be reused
_engine: Engine | None = None


def get_engine() -> Engine:
    """Get or create a SQLAlchemy engine.

    Returns:
        SQLAlchemy engine
    """
    global _engine
    if _engine is None:
        settings = get_settings()
        database_url = settings.database_url
        logger.info("Creating database engine with connection string: %s", database_url)
        _engine = create_engine(database_url)
    return _engine


def initialize_db() -> None:
    """Initialize the database by creating all tables defined in the models.

    This function ensures all table schemas are created in the database
    if they don't already exist.
    """
    engine = get_engine()
    logger.info("Creating database tables if they don't exist")
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialization completed")


def get_session_maker() -> sessionmaker:
    """Get SQLAlchemy session maker.

    Returns:
        SQLAlchemy session maker
    """
    return sessionmaker(autocommit=False, autoflush=False, bind=get_engine())


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """Get a database session using a context manager.

    Yields:
        SQLAlchemy session

    Raises:
        Exception: Any exception that occurs during session use
    """
    session_factory = get_session_maker()
    session = session_factory()
    try:
        logger.debug("Creating new database session")
        yield session
        session.commit()
        logger.debug("Committed database session")
    except SQLAlchemyError as e:
        session.rollback()
        logger.error("Rolling back database session due to error: %s", str(e))
        raise
    finally:
        session.close()
        logger.debug("Closed database session")
