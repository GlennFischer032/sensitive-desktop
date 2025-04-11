"""Base repository module.

This module provides a base repository class with common CRUD operations.
"""

import logging
from typing import Generic, TypeVar

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from desktop_manager.clients.base import APIError


# Type variable for ORM models
T = TypeVar("T")


class BaseRepository(Generic[T]):
    """Base repository class with common CRUD operations.

    This class provides a foundation for all repository classes with common
    database operations such as creating, reading, updating, and deleting entities.
    """

    def __init__(self, session: Session, model_class: type[T]):
        """Initialize the repository with a session and model class.

        Args:
            session: SQLAlchemy session for database operations
            model_class: SQLAlchemy model class
        """
        self.session = session
        self.model_class = model_class
        self.logger = logging.getLogger(self.__class__.__name__)

    def get_all(self, **filters) -> list[T]:
        """Get all entities, optionally filtered.

        Args:
            **filters: Filter criteria as keyword arguments

        Returns:
            List of entities
        """
        try:
            query = self.session.query(self.model_class)

            if filters:
                query = query.filter_by(**filters)

            self.logger.debug("Getting all %s with filters: %s", self.model_class.__name__, filters)
            return query.all()
        except SQLAlchemyError as e:
            error_message = f"Failed to get all {self.model_class.__name__}: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def create(self, entity: T) -> T:
        """Create a new entity.

        Args:
            entity: Entity to create

        Returns:
            Created entity with ID populated
        """
        try:
            self.session.add(entity)
            self.session.commit()
            self.logger.info("Created %s with ID %d", self.model_class.__name__, entity.id)
            return entity
        except SQLAlchemyError as e:
            self.session.rollback()
            error_message = f"Failed to create {self.model_class.__name__}: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def update(self, entity: T) -> T:
        """Update an existing entity.

        Args:
            entity: Entity to update

        Returns:
            Updated entity
        """
        try:
            self.session.commit()
            self.logger.info("Updated %s with ID %d", self.model_class.__name__, entity.id)
            return entity
        except SQLAlchemyError as e:
            self.session.rollback()
            error_message = f"Failed to update {self.model_class.__name__}: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e
