import os
import re

import pytest

# Import all models to ensure they are registered with SQLAlchemy
from desktop_manager.config.settings import Settings
from desktop_manager.core.database import configure_db_for_tests, get_engine
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.sql import text


# Test settings override
def get_test_settings() -> Settings:
    """Get test settings with SQLite configuration."""
    return Settings(
        MYSQL_HOST=os.getenv("MYSQL_HOST", "localhost"),
        MYSQL_PORT=int(os.getenv("MYSQL_PORT", "3306")),
        MYSQL_DATABASE=os.getenv("MYSQL_DATABASE", "test_db"),
        MYSQL_USER=os.getenv("MYSQL_USER", "test_user"),
        MYSQL_PASSWORD=os.getenv("MYSQL_PASSWORD", "test_pass"),
        SECRET_KEY="test_secret_key",
        ADMIN_USERNAME="test_admin",
        ADMIN_PASSWORD="test_admin_pass",
        GUACAMOLE_API_URL="http://test-guacamole:8080",
        GUACAMOLE_USERNAME="test_guac",
        GUACAMOLE_PASSWORD="test_guac_pass",
        OIDC_PROVIDER_URL="http://test-oidc",
        OIDC_CLIENT_ID="test_client",
        OIDC_CLIENT_SECRET="test_secret",
    )


def pytest_addoption(parser):
    """Add custom pytest command line options."""
    parser.addoption(
        "--use-mysql",
        action="store_true",
        default=False,
        help="Run tests against MySQL container instead of SQLite",
    )


@pytest.fixture(scope="session")
def database_url(request):
    """Get database URL based on test configuration."""
    if request.config.getoption("--use-mysql"):
        settings = get_test_settings()
        return f"mysql://{settings.MYSQL_USER}:{settings.MYSQL_PASSWORD}@{settings.MYSQL_HOST}:{settings.MYSQL_PORT}/{settings.MYSQL_DATABASE}"
    return "sqlite:///:memory:"


def sqlite_on_connect(dbapi_connection, connection_record):
    """Enable SQLite foreign keys and other settings."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")  # Better concurrency
    cursor.execute("PRAGMA synchronous=NORMAL")  # Better performance
    cursor.close()


def convert_mysql_to_sqlite(sql: str) -> str:
    """Convert MySQL syntax to SQLite syntax."""
    if not sql or sql.strip().startswith("--") or sql.strip() == "":
        return ""

    # Skip CREATE DATABASE and USE statements
    if "CREATE DATABASE" in sql.upper() or "USE" in sql.upper():
        return ""

    # Convert MySQL-specific syntax to SQLite
    sql = re.sub(
        r"INT\s+AUTO_INCREMENT\s+PRIMARY\s+KEY",
        "INTEGER PRIMARY KEY AUTOINCREMENT",
        sql,
        flags=re.IGNORECASE,
    )
    sql = re.sub(r"BOOLEAN", "INTEGER", sql, flags=re.IGNORECASE)
    sql = re.sub(r"JSON", "TEXT", sql, flags=re.IGNORECASE)
    sql = re.sub(r"TIMESTAMP", "DATETIME", sql, flags=re.IGNORECASE)
    sql = re.sub(r"VARCHAR\(\d+\)", "TEXT", sql, flags=re.IGNORECASE)

    # Handle UNIQUE KEY constraints
    sql = re.sub(
        r"UNIQUE\s+KEY\s+(\w+)\s*\(([\w,\s]+)\)",
        r"UNIQUE (\2)",
        sql,
        flags=re.IGNORECASE,
    )

    # Remove MySQL-specific table options
    sql = re.sub(r"ENGINE\s*=\s*\w+", "", sql, flags=re.IGNORECASE)
    sql = re.sub(r"CHARACTER\s+SET\s+\w+", "", sql, flags=re.IGNORECASE)
    sql = re.sub(r"COLLATE\s+\w+", "", sql, flags=re.IGNORECASE)

    # Handle default timestamp values
    sql = re.sub(
        r"DEFAULT\s+CURRENT_TIMESTAMP(?:\(\))?",
        "DEFAULT (datetime('now', 'localtime'))",
        sql,
        flags=re.IGNORECASE,
    )
    sql = re.sub(
        r"ON\s+UPDATE\s+CURRENT_TIMESTAMP(?:\(\))?", "", sql, flags=re.IGNORECASE
    )

    # Clean up any double spaces and trailing commas before closing parenthesis
    sql = re.sub(r",\s*\)", ")", sql)
    sql = re.sub(r"\s+", " ", sql).strip()

    return sql


@pytest.fixture(scope="session", autouse=True)
def setup_test_db(database_url):
    """Configure the database for testing."""
    is_mysql = "mysql" in database_url

    if is_mysql:
        # Create test database if using MySQL
        engine = create_engine(database_url.rsplit("/", 1)[0])
        database_name = database_url.rsplit("/", 1)[1]

        with engine.connect() as conn:
            conn.execute(text(f"DROP DATABASE IF EXISTS {database_name}"))
            conn.execute(text(f"CREATE DATABASE {database_name}"))
            conn.execute(text(f"USE {database_name}"))

            # Read and execute init.sql
            with open("init.sql") as f:
                sql_content = f.read()
                sql_statements = [
                    stmt.strip() for stmt in sql_content.split(";") if stmt.strip()
                ]
                # Skip the first two statements (CREATE DATABASE and USE)
                for stmt in sql_statements[2:]:
                    conn.execute(text(stmt))
    else:
        # Configure the database
        configure_db_for_tests(database_url)
        engine = get_engine()

        if not is_mysql:
            # SQLite specific configuration
            event.listen(engine, "connect", sqlite_on_connect)

            # Create tables for SQLite
            with engine.connect() as conn:
                # Users table
                conn.execute(
                    text(
                        """
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        password_hash TEXT,
                        email TEXT NOT NULL UNIQUE,
                        organization TEXT,
                        is_admin INTEGER NOT NULL DEFAULT 0,
                        created_at DATETIME DEFAULT (datetime('now', 'localtime')),
                        sub TEXT UNIQUE,
                        given_name TEXT,
                        family_name TEXT,
                        locale TEXT,
                        email_verified INTEGER DEFAULT 0,
                        last_login DATETIME
                    )
                """
                    )
                )

                # Create indexes for users table
                conn.execute(
                    text("CREATE INDEX IF NOT EXISTS idx_username ON users(username)")
                )
                conn.execute(
                    text("CREATE INDEX IF NOT EXISTS idx_email ON users(email)")
                )
                conn.execute(text("CREATE INDEX IF NOT EXISTS idx_sub ON users(sub)"))

                # Social Auth Association table
                conn.execute(
                    text(
                        """
                    CREATE TABLE IF NOT EXISTS social_auth_association (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        provider TEXT NOT NULL,
                        provider_user_id TEXT NOT NULL,
                        provider_name TEXT,
                        created_at DATETIME DEFAULT (datetime('now', 'localtime')),
                        last_used DATETIME,
                        extra_data TEXT,
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                        UNIQUE (provider, provider_user_id)
                    )
                """
                    )
                )

                # PKCE State table
                conn.execute(
                    text(
                        """
                    CREATE TABLE IF NOT EXISTS pkce_state (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        state TEXT NOT NULL UNIQUE,
                        code_verifier TEXT NOT NULL,
                        created_at DATETIME DEFAULT (datetime('now', 'localtime')),
                        expires_at DATETIME,
                        used INTEGER DEFAULT 0
                    )
                """
                    )
                )

                # Create indexes for pkce_state table
                conn.execute(
                    text("CREATE INDEX IF NOT EXISTS idx_state ON pkce_state(state)")
                )
                conn.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS idx_expires ON pkce_state(expires_at)"
                    )
                )

                # Connections table
                conn.execute(
                    text(
                        """
                    CREATE TABLE IF NOT EXISTS connections (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL UNIQUE,
                        created_at DATETIME DEFAULT (datetime('now', 'localtime')),
                        created_by TEXT,
                        guacamole_connection_id TEXT NOT NULL,
                        target_host TEXT,
                        target_port INTEGER,
                        password TEXT,
                        protocol TEXT DEFAULT 'vnc',
                        FOREIGN KEY (created_by) REFERENCES users(username)
                    )
                """
                    )
                )

                conn.commit()

    yield database_url

    # Clean up after tests
    if is_mysql:
        engine = create_engine(database_url.rsplit("/", 1)[0])
        with engine.connect() as conn:
            conn.execute(text(f"DROP DATABASE IF EXISTS {database_name}"))
    else:
        # For SQLite in-memory database, no cleanup needed as it's destroyed automatically
        pass


@pytest.fixture(autouse=True)
def cleanup_tables(test_db):
    """Clean up tables after each test."""
    yield
    try:
        # Clean up both users and connections tables
        test_db.execute(text("DELETE FROM connections"))
        test_db.execute(text("DELETE FROM users"))
        test_db.commit()
    except Exception:
        test_db.rollback()
        raise


@pytest.fixture(autouse=True)
def setup_test_session(setup_test_db):
    """Set up a test session that commits after each test."""
    connection = get_engine().connect()
    session = Session(bind=connection)

    yield session

    session.commit()  # Commit changes instead of rolling back
    session.close()
    connection.close()


@pytest.fixture()
def test_db(setup_test_session):
    """Provide a database session for tests."""
    return setup_test_session


@pytest.fixture()
def test_engine():
    """Provide the SQLAlchemy engine for tests."""
    return get_engine()


@pytest.fixture()
def client(monkeypatch):
    """Create a test client with database and settings overrides."""
    from desktop_manager.main import create_app

    # Override get_settings
    monkeypatch.setattr(
        "desktop_manager.config.settings.get_settings", get_test_settings
    )

    # Create test app
    app = create_app()
    app.config["TESTING"] = True

    return app.test_client()


# Mock Guacamole client
@pytest.fixture()
def mock_guacamole_client(mocker):
    """Create a mock Guacamole client."""
    mock = mocker.Mock()
    # Add common mock methods here
    return mock
