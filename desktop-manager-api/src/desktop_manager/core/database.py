from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool
from sqlalchemy.exc import OperationalError
from sqlalchemy.engine import Engine
from typing import Generator, Optional
from desktop_manager.config.settings import get_settings
import logging
import time

__all__ = ['init_db', 'get_db', 'Base']

logging.basicConfig(level=logging.INFO)
logger: logging.Logger = logging.getLogger(__name__)

settings = get_settings()

SQLALCHEMY_DATABASE_URL: str = f"mysql://{settings.MYSQL_USER}:{settings.MYSQL_PASSWORD}@{settings.MYSQL_HOST}:{settings.MYSQL_PORT}/{settings.MYSQL_DATABASE}"

def create_db_engine(retries: int = 5, delay: int = 2) -> Engine:
    for attempt in range(retries):
        try:
            logger.info(f"Attempting to connect to database (attempt {attempt + 1}/{retries})")
            engine: Engine = create_engine(
                SQLALCHEMY_DATABASE_URL,
                poolclass=QueuePool,
                pool_size=5,
                max_overflow=10,
                pool_pre_ping=True,
                pool_recycle=3600
            )
            # Test the connection
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            logger.info("Successfully connected to database")
            return engine
        except OperationalError as e:
            if attempt < retries - 1:
                logger.warning(f"Failed to connect to database: {str(e)}")
                logger.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                logger.error("Failed to connect to database after all retries")
                raise
        except Exception as e:
            logger.error(f"Unexpected error while connecting to database: {str(e)}")
            raise

# Create engine with retry logic
engine: Engine = create_db_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db() -> Generator[Session, None, None]:
    db: Session = SessionLocal()
    try:
        yield db
    except Exception as e:
        logger.error(f"Database session error: {str(e)}")
        raise
    finally:
        db.close()

def init_db() -> None:
    """Initialize the database by creating all tables."""
    logger.info("Initializing database...")
    try:
        from desktop_manager.api.models.base import Base
        Base.metadata.create_all(bind=engine)
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        raise
