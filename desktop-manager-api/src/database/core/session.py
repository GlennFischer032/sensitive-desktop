"""Session management module.

This module provides functions for managing database sessions.
"""

from collections.abc import Generator
from contextlib import contextmanager
from functools import wraps
import logging

from config.settings import get_settings
from flask import g, request
from schemas.base import Base
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker


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
        _engine = create_engine(database_url)
    return _engine


def initialize_db() -> None:
    """Initialize the database by creating all tables defined in the models.

    This function ensures all table schemas are created in the database
    if they don't already exist.
    """
    engine = get_engine()
    logger.debug("Creating database tables if they don't exist")
    Base.metadata.create_all(bind=engine)
    logger.debug("Database initialization completed")


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
    engine = get_engine()  # Ensure engine is initialized
    with Session(engine) as session:
        try:
            yield session
        except Exception:
            raise


def with_db_session(func):
    """Decorator to manage database sessions for Flask routes."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        with get_db_session() as session:
            request.db_session = session
            try:
                result = func(*args, **kwargs)
                return result
            except Exception:
                raise
            finally:
                if hasattr(g, "db_session"):
                    delattr(g, "db_session")

    return wrapper
