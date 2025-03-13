from typing import Generator

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import DeclarativeMeta, Session


Base: DeclarativeMeta = declarative_base()


def get_db() -> Generator[Session, None, None]:
    from desktop_manager.core.database import get_session_factory

    SessionFactory = get_session_factory()
    db = SessionFactory()
    try:
        yield db
    finally:
        db.close()
