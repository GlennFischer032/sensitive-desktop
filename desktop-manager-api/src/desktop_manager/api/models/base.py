from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, DeclarativeMeta
from typing import Generator

Base: DeclarativeMeta = declarative_base()

def get_db() -> Generator[Session, None, None]:
    from desktop_manager.core.database import SessionLocal
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close() 