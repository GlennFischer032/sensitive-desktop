import logging
import time

from config.settings import get_settings
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool, StaticPool


__all__ = ["get_session_factory"]
logger: logging.Logger = logging.getLogger(__name__)

# Global variables to store engine and session factory
_engine: Engine | None = None
_session_factory: sessionmaker | None = None


def get_database_url() -> str:
    """Get the database URL from settings."""
    settings = get_settings()
    return f"postgresql://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DATABASE}"


def create_db_engine(db_url: str | None = None, retries: int = 5, delay: int = 2) -> Engine:
    """Create database engine with retry logic."""
    if db_url is None:
        db_url = get_database_url()

    logger.debug("Database URL: %s", db_url)

    for attempt in range(retries):
        try:
            logger.debug(
                "Attempting to connect to database (attempt %s/%s)",
                attempt + 1,
                retries,
            )
            engine: Engine = create_engine(
                db_url,
                poolclass=QueuePool,
                pool_size=5,
                max_overflow=10,
                pool_pre_ping=True,
                pool_recycle=3600,
            )
            # Test the connection
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            logger.debug("Successfully connected to database")
            return engine
        except OperationalError as e:
            if attempt < retries - 1:
                logger.warning("Failed to connect to database: %s", str(e))
                logger.debug("Retrying in %s seconds...", delay)
                time.sleep(delay)
            else:
                logger.error("Failed to connect to database after all retries")
                raise
        except Exception as e:
            logger.error("Unexpected error while connecting to database: %s", str(e))
            raise


def get_engine() -> Engine:
    """Get or create database engine."""
    global _engine
    if _engine is None:
        _engine = create_db_engine()
    return _engine


def get_session_factory() -> sessionmaker:
    """Get or create session factory."""
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())
    return _session_factory


def configure_db_for_tests(db_url: str) -> None:
    """Configure database for testing environment."""
    global _engine, _session_factory
    # Clear existing engine and session factory
    _engine = None
    _session_factory = None

    # Create new engine with SQLite-specific configuration
    _engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False} if "sqlite" in db_url else {},
        poolclass=StaticPool if "sqlite" in db_url else QueuePool,
    )

    # Enable SQLite foreign keys if using SQLite
    if "sqlite" in db_url:

        def _enable_sqlite_foreign_keys(connection, _):
            cursor = connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON;")
            cursor.close()

        event.listen(_engine, "connect", _enable_sqlite_foreign_keys)

    # Create session factory
    _session_factory = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
