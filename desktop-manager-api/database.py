from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import QueuePool
from sqlalchemy.exc import OperationalError
from config import Config
import logging
import time

__all__ = ['init_db', 'get_db', 'Base']

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_db_engine(retries=5, delay=2):
    for attempt in range(retries):
        try:
            logger.info(f"Attempting to connect to database (attempt {attempt + 1}/{retries})")
            engine = create_engine(
                Config.DATABASE_URL,
                pool_size=10,
                max_overflow=20,
                pool_pre_ping=True,
                pool_recycle=3600,
                poolclass=QueuePool,
                connect_args={
                    'connect_timeout': 10
                }
            )
            # Test the connection
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
                conn.commit()  # Commit any pending transaction
            logger.info("Successfully connected to database")
            return engine
        except OperationalError as e:
            if attempt < retries - 1:
                logger.warning(f"Failed to connect to database: {str(e)}. Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                logger.error(f"Failed to connect to database after {retries} attempts: {str(e)}")
                raise

# Create engine with retry logic
engine = create_db_engine()

@event.listens_for(engine, 'engine_connect')
def ping_connection(connection, branch):
    if branch:
        return

    try:
        with connection.begin():
            connection.scalar(text("SELECT 1"))
    except Exception:
        logger.warning("Database connection was invalid, reconnecting...")
        connection.invalidate()
        raise

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        logger.error(f"Database session error: {str(e)}")
        raise
    finally:
        db.close()

def init_db():
    """Initialize the database by creating all tables."""
    logger.info("Initializing database...")
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        raise
