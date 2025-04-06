import os
import re

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.sql import text

# Import all models to ensure they are registered with SQLAlchemy
from desktop_manager.config.settings import Settings
from desktop_manager.core.database import configure_db_for_tests, get_engine


# Test settings override
def get_test_settings() -> Settings:
    """Get test settings with SQLite configuration."""
    return Settings(
        # Use in-memory SQLite by default for isolated testing
        database_url=os.getenv("TEST_DATABASE_URL", "sqlite:///:memory:"),
        POSTGRES_HOST=os.getenv("POSTGRES_HOST", "localhost"),
        POSTGRES_PORT=int(os.getenv("POSTGRES_PORT", "5432")),
        POSTGRES_DB=os.getenv("POSTGRES_DB", "test_db"),
        POSTGRES_USER=os.getenv("POSTGRES_USER", "test_user"),
        POSTGRES_PASSWORD=os.getenv("POSTGRES_PASSWORD", "test_pass"),
        SECRET_KEY="test_secret_key",
        ADMIN_USERNAME="test_admin",
        ADMIN_PASSWORD="test_admin_pass",
        GUACAMOLE_URL="http://test-guacamole:8080/guacamole",
        GUACAMOLE_USERNAME="test_guac",
        GUACAMOLE_PASSWORD="test_guac_pass",
        OIDC_PROVIDER_URL="http://test-oidc",
        OIDC_CLIENT_ID="test_client",
        OIDC_CLIENT_SECRET="test_secret",
    )


def pytest_addoption(parser):
    """Add custom pytest command line options."""
    parser.addoption(
        "--use-postgres",
        action="store_true",
        default=False,
        help="Run tests against PostgreSQL container instead of SQLite",
    )


@pytest.fixture(scope="session")
def database_url(request):
    """Get database URL based on test configuration."""
    if request.config.getoption("--use-postgres"):
        settings = get_test_settings()
        return f"postgresql://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"
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
    sql = re.sub(r"ON\s+UPDATE\s+CURRENT_TIMESTAMP(?:\(\))?", "", sql, flags=re.IGNORECASE)

    # Clean up any double spaces and trailing commas before closing parenthesis
    sql = re.sub(r",\s*\)", ")", sql)
    sql = re.sub(r"\s+", " ", sql).strip()

    return sql


@pytest.fixture(scope="session", autouse=True)
def setup_test_db(database_url):
    """Configure the database for testing."""
    is_postgres = "postgresql" in database_url

    if is_postgres:
        # Create test database if using PostgreSQL
        engine = create_engine(database_url.rsplit("/", 1)[0])
        database_name = database_url.rsplit("/", 1)[1]

        with engine.connect() as conn:
            conn.execute(text(f"DROP DATABASE IF EXISTS {database_name}"))
            conn.execute(text(f"CREATE DATABASE {database_name}"))
            conn.execute(text(f"USE {database_name}"))

            # Read and execute init.sql
            with open("init.sql") as f:
                sql_content = f.read()
                sql_statements = [stmt.strip() for stmt in sql_content.split(";") if stmt.strip()]
                # Skip the first two statements (CREATE DATABASE and USE)
                for stmt in sql_statements[2:]:
                    conn.execute(text(stmt))
    else:
        # Configure the database
        configure_db_for_tests(database_url)
        engine = get_engine()

        if not is_postgres:
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
                        name TEXT,
                        locale TEXT,
                        email_verified INTEGER DEFAULT 0,
                        last_login DATETIME
                    )
                """
                    )
                )

                # Create indexes for users table
                conn.execute(text("CREATE INDEX IF NOT EXISTS idx_username ON users(username)"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS idx_email ON users(email)"))
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
                conn.execute(text("CREATE INDEX IF NOT EXISTS idx_state ON pkce_state(state)"))
                conn.execute(
                    text("CREATE INDEX IF NOT EXISTS idx_expires ON pkce_state(expires_at)")
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
                        is_stopped INTEGER DEFAULT 0,
                        persistent_home INTEGER DEFAULT 1,
                        desktop_configuration_id INTEGER,
                        FOREIGN KEY (created_by) REFERENCES users(username),
                        FOREIGN KEY (desktop_configuration_id) REFERENCES desktop_configurations(id)
                    )
                """
                    )
                )

                # Desktop Configurations table
                conn.execute(
                    text(
                        """
                    CREATE TABLE IF NOT EXISTS desktop_configurations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL UNIQUE,
                        description TEXT,
                        image TEXT NOT NULL,
                        created_at DATETIME DEFAULT (datetime('now', 'localtime')),
                        created_by TEXT,
                        is_public INTEGER DEFAULT 0,
                        min_cpu INTEGER DEFAULT 1,
                        max_cpu INTEGER DEFAULT 4,
                        min_ram TEXT DEFAULT '4096Mi',
                        max_ram TEXT DEFAULT '16384Mi',
                        FOREIGN KEY (created_by) REFERENCES users(username) ON DELETE CASCADE
                    )
                """
                    )
                )

                # Create index for desktop_configurations table
                conn.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS idx_desktop_config_name ON desktop_configurations(name)"
                    )
                )

                # Desktop Configuration Access table
                conn.execute(
                    text(
                        """
                    CREATE TABLE IF NOT EXISTS desktop_configuration_access (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        desktop_configuration_id INTEGER NOT NULL,
                        username TEXT NOT NULL,
                        created_at DATETIME DEFAULT (datetime('now', 'localtime')),
                        FOREIGN KEY (desktop_configuration_id) REFERENCES desktop_configurations(id) ON DELETE CASCADE,
                        FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
                    )
                """
                    )
                )

                # Create indexes for desktop_configuration_access table
                conn.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS idx_desktop_config_access_username ON desktop_configuration_access(username)"
                    )
                )
                conn.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS idx_desktop_config_access_config_id ON desktop_configuration_access(desktop_configuration_id)"
                    )
                )

                conn.commit()

    yield database_url

    # Clean up after tests
    if is_postgres:
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


@pytest.fixture
def test_db(setup_test_session):
    """Provide a database session for tests."""
    return setup_test_session


@pytest.fixture
def test_engine():
    """Provide the SQLAlchemy engine for tests."""
    return get_engine()


@pytest.fixture
def client(monkeypatch):
    """Create a test client with database and settings overrides."""
    from desktop_manager.main import create_app

    # Override get_settings
    monkeypatch.setattr("desktop_manager.config.settings.get_settings", get_test_settings)

    # Create test app
    app = create_app()
    app.config["TESTING"] = True

    return app.test_client()


# Mock Guacamole client
@pytest.fixture
def mock_guacamole_client(mocker):
    """Create a mock Guacamole client."""
    mock = mocker.Mock()
    # Add common mock methods here
    return mock


@pytest.fixture(autouse=True)
def mock_database_client(monkeypatch, test_db):
    """Mock the database client to use the test_db session.

    This fixture replaces the real database client with a mock implementation
    that uses the test_db session for all operations.
    """
    from tests.mocks import MockDatabaseClient

    # Create a mock database client that uses the test_db session
    mock_client = MockDatabaseClient(session=test_db)

    # Patch the client_factory's _database_client attribute
    monkeypatch.setattr(
        "desktop_manager.clients.factory.client_factory._database_client", mock_client
    )

    # Patch the factory method to return our mock client
    monkeypatch.setattr(
        "desktop_manager.clients.factory.client_factory.get_database_client", lambda: mock_client
    )

    # Patch the direct factory function to return our mock client
    monkeypatch.setattr("desktop_manager.clients.factory.get_database_client", lambda: mock_client)

    return mock_client


@pytest.fixture(autouse=True)
def mock_auth_decorators(monkeypatch, test_db):
    """Mock authentication decorators to avoid real database connections.

    This fixture replaces the token_required and admin_required decorators
    with versions that use the test_db session directly.
    """
    from functools import wraps

    from flask import jsonify, request
    import jwt

    class MockUser:
        """Simple user class for testing that mimics the User model."""

        def __init__(self, user_id, username, is_admin):
            self.id = user_id
            self.username = username
            self.is_admin = is_admin
            self.email = f"{username}@example.com"
            self.organization = "Test Org"

        def __repr__(self):
            return f"<MockUser id={self.id} username={self.username} is_admin={self.is_admin}>"

    def mock_token_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            print("DEBUG: Executing mock_token_required decorator")
            try:
                token = None
                auth_header = request.headers.get("Authorization")

                if auth_header and auth_header.startswith("Bearer "):
                    token = auth_header.split(" ")[1]

                if not token:
                    print("DEBUG: No token found in request")
                    return jsonify({"message": "Token is missing!"}), 401

                try:
                    # First attempt: Try decoding token as JWT
                    payload = jwt.decode(token, "test_secret_key", algorithms=["HS256"])
                    print(f"DEBUG TOKEN PAYLOAD: {payload}")

                    user_id = payload.get("user_id", 999)
                    username = payload.get("username", "unknown")
                    is_admin = bool(payload.get("is_admin", False))

                    # Create mock user
                    current_user = MockUser(user_id=user_id, username=username, is_admin=is_admin)
                    print(f"DEBUG: Created user from JWT: {current_user}")

                    # Set user on request
                    request.current_user = current_user
                except jwt.InvalidTokenError:
                    # Second attempt: Mock OIDC token validation
                    print("DEBUG: JWT validation failed, trying OIDC token validation")

                    # Mock the userinfo response with a valid 'sub' field
                    # This simulates the userinfo endpoint for OIDC
                    userinfo = {
                        "success": True,
                        "sub": "123",  # Add the missing 'sub' field
                        "email": "test@example.com",
                        "name": "Test User",
                        "username": "testuser",
                    }

                    print(f"DEBUG: Mocked userinfo response: {userinfo}")

                    # Extract user ID from JWT payload if possible
                    try:
                        raw_payload = jwt.decode(token, options={"verify_signature": False})
                        user_id = raw_payload.get("user_id", 999)
                        username = raw_payload.get("username", "testuser")
                        is_admin = bool(raw_payload.get("is_admin", False))
                    except Exception:
                        # Default values if JWT decoding fails completely
                        user_id = 999
                        username = "testuser"
                        is_admin = False

                    # Create mock user for OIDC
                    current_user = MockUser(user_id=user_id, username=username, is_admin=is_admin)
                    print(f"DEBUG: Created user from OIDC: {current_user}")

                    # Set user on request
                    request.current_user = current_user

                print(
                    f"DEBUG: Set current_user on request with is_admin={request.current_user.is_admin}"
                )
                return f(*args, **kwargs)
            except Exception as e:
                print(f"DEBUG: Exception in mock_token_required: {e!s}")
                return jsonify({"message": "Token is invalid!"}), 401

        return decorated

    def mock_admin_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            print("DEBUG: Executing mock_admin_required decorator")

            # Get current_user from request
            current_user = getattr(request, "current_user", None)
            if not current_user:
                print("DEBUG: No current_user found on request!")
                return jsonify({"message": "Authentication required!"}), 401

            print(f"DEBUG: User in admin_required: {current_user}")
            print(f"DEBUG: is_admin value: {current_user.is_admin}")

            # Check if user is admin
            if not current_user.is_admin:
                print(f"DEBUG: User {current_user.username} is not an admin")
                return jsonify({"message": "Admin privilege required!"}), 403

            print(f"DEBUG: User {current_user.username} is admin, proceeding")
            return f(*args, **kwargs)

        return decorated

    # Patch all instances of the authentication decorators
    # Core module patches
    print("\nDEBUG PATCHING: Patching core auth decorators")
    monkeypatch.setattr("desktop_manager.core.auth.token_required", mock_token_required)
    monkeypatch.setattr("desktop_manager.core.auth.admin_required", mock_admin_required)

    # Route-specific patches
    print("DEBUG PATCHING: Patching user_routes decorators")
    monkeypatch.setattr(
        "desktop_manager.api.routes.user_routes.token_required", mock_token_required
    )
    monkeypatch.setattr(
        "desktop_manager.api.routes.user_routes.admin_required", mock_admin_required
    )

    print("DEBUG PATCHING: Patching connection_routes decorators")
    monkeypatch.setattr(
        "desktop_manager.api.routes.connection_routes.token_required", mock_token_required
    )
    # Don't patch admin_required for connection_routes since it doesn't use this decorator

    # Auth routes
    print("DEBUG PATCHING: Patching auth_routes decorators")
    monkeypatch.setattr(
        "desktop_manager.api.routes.auth_routes.token_required", mock_token_required
    )
    monkeypatch.setattr(
        "desktop_manager.api.routes.auth_routes.admin_required", mock_admin_required
    )

    # Return the mock decorators for potential use in tests
    print("DEBUG PATCHING: Patching finished")
    return {"token_required": mock_token_required, "admin_required": mock_admin_required}
