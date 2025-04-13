"""Base module for SQLAlchemy models.

This module defines the base class for all SQLAlchemy models.
"""

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase


# Define naming convention for SQLAlchemy constraints
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

# Create metadata with naming convention and proper ordering for circular dependencies
metadata = MetaData(naming_convention=convention)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""

    metadata = metadata
