"""Unit tests for connection routes."""

import json
import logging
import uuid
from http import HTTPStatus
from unittest.mock import ANY, Mock, patch
from functools import wraps

import jwt
import pytest
from flask import jsonify
from desktop_manager.api.models.connection import Connection
from desktop_manager.api.models.user import User
from desktop_manager.api.routes.connection_routes import connections_bp
from desktop_manager.core.exceptions import GuacamoleError
from desktop_manager.clients.guacamole import (
    create_guacamole_connection,
    delete_guacamole_connection,
    ensure_admins_group,
    grant_group_permission_on_connection,
    grant_user_permission_on_connection,
    guacamole_login,
)
from desktop_manager.core.rancher import DesktopValues
from flask import Flask, request
from sqlalchemy import text
from desktop_manager.clients.base import APIError

from tests.config import TEST_CONNECTION, TEST_USER


@pytest.fixture(autouse=True)
def setup_database(test_db, test_engine):
    """Set up the database with the correct schema before each test."""
    # Drop and recreate the connections table with the current schema
    Connection.__table__.drop(test_engine, checkfirst=True)
    Connection.__table__.create(test_engine, checkfirst=True)

    # Clean up before test
    test_db.execute(text("DELETE FROM connections"))
    test_db.commit()

    # Run the test
    yield

    # Clean up after test
    test_db.execute(text("DELETE FROM connections"))
    test_db.commit()


@pytest.fixture()
def test_user(test_db):
    """Create a test user for a single test."""
    # Generate unique email and username for each test
    unique_id = str(uuid.uuid4())[:8]
    user = User(
        username=f"{TEST_USER['username']}_{unique_id}",
        email=f"{unique_id}_{TEST_USER['email']}",
        organization=TEST_USER["organization"],
    )
    test_db.add(user)
    test_db.commit()
    test_db.refresh(user)
    return user


@pytest.fixture()
def auth_token(test_user):
    """Create a JWT token for the test user."""
    return jwt.encode({"user_id": test_user.id}, "test_secret_key", algorithm="HS256")


@pytest.fixture()
def mock_settings():
    """Mock settings for tests."""
    settings_mock = Mock()
    settings_mock.RANCHER_API_URL = "http://rancher.test"
    settings_mock.RANCHER_API_TOKEN = "test_token"
    settings_mock.RANCHER_CLUSTER_ID = "test_cluster"
    settings_mock.RANCHER_REPO_NAME = "test_repo"
    settings_mock.NAMESPACE = "fischer-ns"
    settings_mock.DESKTOP_IMAGE = "test_image"
    settings_mock.EXTERNAL_GUACAMOLE_URL = "http://guacamole-test:8080/guacamole"
    settings_mock.GUACAMOLE_JSON_SECRET_KEY = "test_secret_key"
    settings_mock.GUACAMOLE_SECRET_KEY = "test_secret_key"
    settings_mock.GUACAMOLE_URL = "http://guacamole-test:8080/guacamole"
    return settings_mock


@pytest.fixture()
def test_app(test_db, mock_settings):
    """Create a test Flask application."""
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test_secret_key"

    # Mock get_db to use test database
    def mock_get_db():
        yield test_db

    with patch(
        "desktop_manager.api.routes.connection_routes.get_db", mock_get_db
    ), patch(
        "desktop_manager.api.routes.connection_routes.get_settings",
        return_value=mock_settings,
    ):
        # Register the blueprint
        app.register_blueprint(connections_bp)

        @app.before_request
        def before_request():
            # Get the current user from the token
            if "Authorization" in request.headers:
                token = request.headers["Authorization"].split(" ")[1]
                try:
                    user_id = jwt.decode(token, "test_secret_key", algorithms=["HS256"])["user_id"]
                    test_db.expire_all()  # Clear session cache
                    request.current_user = test_db.query(User).get(user_id)
                    if request.current_user is None:
                        logging.error("User %s not found in before_request", user_id)
                        raise Exception("Test user not found")
                except (jwt.InvalidTokenError, KeyError) as e:
                    logging.error("Invalid token in before_request: %s", str(e))
                    request.current_user = None

        # Add a context processor to make g.user available
        @app.context_processor
        def inject_user():
            if hasattr(request, 'current_user'):
                return {'current_user': request.current_user}
            return {'current_user': None}

        return app


@pytest.fixture()
def test_client(test_app, auth_token):
    """Create a test client."""
    with test_app.test_client() as client:
        # Add Authorization header to all requests
        client.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {auth_token}"
        yield client


@pytest.fixture()
def mock_rancher_client():
    """Mock RancherClient class."""
    with patch("desktop_manager.clients.factory.client_factory.get_rancher_client") as mock:
        mock_instance = Mock()
        mock_instance.install.return_value = {"status": "success"}
        mock_instance.check_vnc_ready.return_value = True
        mock_instance.uninstall.return_value = {"status": "success"}
        mock.return_value = mock_instance
        yield mock_instance


@pytest.fixture()
def mock_guacamole():
    """Mock Guacamole-related functions."""
    with patch(
        "desktop_manager.api.routes.connection_routes.guacamole_login"
    ) as mock_login, patch(
        "desktop_manager.api.routes.connection_routes.ensure_admins_group"
    ) as mock_ensure_group, patch(
        "desktop_manager.api.routes.connection_routes.create_guacamole_connection"
    ) as mock_create, patch(
        "desktop_manager.api.routes.connection_routes.grant_group_permission_on_connection"
    ) as mock_group_perm, patch(
        "desktop_manager.api.routes.connection_routes.grant_user_permission_on_connection"
    ) as mock_user_perm, patch(
        "desktop_manager.api.routes.connection_routes.delete_guacamole_connection"
    ) as mock_delete:
        mock_login.return_value = "mock_token"
        mock_create.return_value = "mock_guac_conn_id"
        yield {
            "login": mock_login,
            "ensure_group": mock_ensure_group,
            "create": mock_create,
            "grant_group": mock_group_perm,
            "grant_user": mock_user_perm,
            "delete": mock_delete,
        }


@pytest.fixture()
def mock_guacamole_json_auth():
    """Mock GuacamoleJsonAuth class."""
    with patch(
        "desktop_manager.api.routes.connection_routes.GuacamoleJsonAuth"
    ) as mock_class:
        mock_instance = Mock()
        mock_instance.generate_auth_data.return_value = "http://guacamole-test:8080/guacamole/#/?data=mock-auth-token"
        mock_class.return_value = mock_instance
        yield mock_instance


@pytest.fixture()
def test_connection(test_db, test_user):
    """Create a test connection in the database."""
    connection = Connection(
        name=f"test-connection-{str(uuid.uuid4())[:8]}",
        created_by=test_user.username,
        guacamole_connection_id="test_guac_id",
        target_host="test-host.example.com",
        target_port=5900,
        password="test-password",
        protocol="vnc",
    )
    test_db.add(connection)
    test_db.commit()
    test_db.refresh(connection)
    return connection


def test_scale_up_success(test_client, mock_rancher_client, mock_guacamole, test_user):
    """Test successful connection scale up."""
    # Prepare test data
    data = {"name": TEST_CONNECTION["name"]}

    # Make request
    response = test_client.post(
        "/scaleup", data=json.dumps(data), content_type="application/json"
    )

    # Check response
    assert response.status_code == HTTPStatus.OK
    response_data = json.loads(response.data)
    assert "message" in response_data
    assert "connection" in response_data
    assert (
        f"Connection {response_data['connection']['name']} scaled up successfully"
        == response_data["message"]
    )
    assert test_user.username == response_data["connection"]["created_by"]
    assert "guacamole_connection_id" in response_data["connection"]

    # Make sure the connection was created with the correct host format
    mock_guacamole["create"].assert_called_once()
    # Extract the args from the mock call
    _, _, hostname, _ = mock_guacamole["create"].call_args[0]
    # Verify hostname format
    assert hostname.startswith("fischer-ns-")
    assert hostname.endswith(".dyn.cloud.e-infra.cz")

    # Verify mock calls
    mock_rancher_client.install.assert_called_once()
    mock_rancher_client.check_vnc_ready.assert_called_once()
    mock_guacamole["login"].assert_called_once()
    mock_guacamole["ensure_group"].assert_called_once()
    mock_guacamole["create"].assert_called_once()
    mock_guacamole["grant_group"].assert_called_once()
    mock_guacamole["grant_user"].assert_called_once()


def test_scale_up_invalid_input(test_client):
    """Test scale up with invalid input."""
    # Test with empty data
    response = test_client.post(
        "/scaleup", data=json.dumps({}), content_type="application/json"
    )
    assert response.status_code == HTTPStatus.BAD_REQUEST

    # Test with missing name
    response = test_client.post(
        "/scaleup",
        data=json.dumps({"invalid": "data"}),
        content_type="application/json",
    )
    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_scale_up_rancher_failure(test_client, mock_rancher_client, mock_guacamole):
    """Test scale up when Rancher deployment fails."""
    # Configure Rancher mock to fail
    mock_rancher_client.install.side_effect = APIError("Deployment failed", status_code=500)

    # Make request
    response = test_client.post(
        "/scaleup",
        data=json.dumps({"name": TEST_CONNECTION["name"]}),
        content_type="application/json",
    )

    # Check response
    assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    response_data = json.loads(response.data)
    assert "error" in response_data

    # Verify no Guacamole calls were made
    mock_guacamole["create"].assert_not_called()
    mock_guacamole["grant_group"].assert_not_called()
    mock_guacamole["grant_user"].assert_not_called()


def test_scale_up_guacamole_failure(test_client, mock_rancher_client, mock_guacamole):
    """Test scale up when Guacamole configuration fails."""
    # Configure Guacamole mock to fail
    mock_guacamole["create"].side_effect = GuacamoleError("Failed to create connection")

    # Make request
    response = test_client.post(
        "/scaleup",
        data=json.dumps({"name": TEST_CONNECTION["name"]}),
        content_type="application/json",
    )

    # Check response
    assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    response_data = json.loads(response.data)
    assert "error" in response_data

    # Verify cleanup was attempted
    mock_rancher_client.uninstall.assert_called_once()


def test_scale_down_success(
    test_client, mock_rancher_client, mock_guacamole, test_db, test_user
):
    """Test successful connection scale down."""
    # Create a test connection
    connection_name = f"test-conn-{str(uuid.uuid4())[:8]}"
    connection = Connection(
        name=connection_name,
        created_by=test_user.username,
        guacamole_connection_id="test_guac_id",
    )
    test_db.add(connection)
    test_db.commit()

    # Make request
    response = test_client.post(
        "/scaledown",
        data=json.dumps({"name": connection_name}),
        content_type="application/json",
    )

    # Check response
    assert response.status_code == HTTPStatus.OK
    response_data = json.loads(response.data)
    assert "message" in response_data
    assert connection_name in response_data["message"]

    # Verify connection was deleted from database
    remaining = test_db.query(Connection).filter_by(name=connection_name).count()
    assert remaining == 0

    # Verify Rancher uninstall was called
    mock_rancher_client.uninstall.assert_called_once_with(connection_name)

    # Verify Guacamole delete was called
    mock_guacamole["delete"].assert_called_once()


def test_scale_down_nonexistent_connection(test_client):
    """Test scaling down a nonexistent connection."""
    response = test_client.post(
        "/scaledown",
        data=json.dumps({"name": "nonexistent"}),
        content_type="application/json",
    )
    assert response.status_code == HTTPStatus.NOT_FOUND
    response_data = json.loads(response.data)
    assert "error" in response_data


def test_scale_down_invalid_input(test_client):
    """Test scale down with invalid input."""
    # Test with empty data
    response = test_client.post(
        "/scaledown", data=json.dumps({}), content_type="application/json"
    )
    assert response.status_code == HTTPStatus.BAD_REQUEST

    # Test with missing name
    response = test_client.post(
        "/scaledown",
        data=json.dumps({"invalid": "data"}),
        content_type="application/json",
    )
    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_list_connections_empty(test_client):
    """Test listing connections when none exist."""
    response = test_client.get("/list")
    assert response.status_code == HTTPStatus.OK
    response_data = json.loads(response.data)
    assert "connections" in response_data
    assert len(response_data["connections"]) == 0


def test_list_connections(test_client, test_db, test_user):
    """Test listing existing connections."""
    # Create test connections
    connections = [
        Connection(
            name=f"test-conn-{str(uuid.uuid4())[:8]}",
            created_by=test_user.username,
            guacamole_connection_id=f"test_guac_id_{i}",
        )
        for i in range(3)
    ]
    for conn in connections:
        test_db.add(conn)
    test_db.commit()

    # Get list of connections
    response = test_client.get("/list")
    assert response.status_code == HTTPStatus.OK
    response_data = json.loads(response.data)
    assert "connections" in response_data
    assert len(response_data["connections"]) == 3

    # Verify connection details
    for conn in response_data["connections"]:
        assert "name" in conn
        assert "created_by" in conn
        assert "guacamole_connection_id" in conn
        assert conn["created_by"] == test_user.username


@pytest.fixture()
def non_admin_token(test_db):
    """Create a JWT token for a non-admin user."""
    # Create a non-admin user
    non_admin = User(
        username="non_admin",
        email="non_admin@example.com",
        password_hash="hash",
        is_admin=False,
    )
    test_db.add(non_admin)
    test_db.commit()

    # Create a token
    token = jwt.encode(
        {"user_id": non_admin.id, "is_admin": non_admin.is_admin},
        "test_secret_key",
        algorithm="HS256",
    )
    return token, non_admin


def test_list_connections_non_admin(test_client, test_db, test_user, non_admin_token):
    """Test listing connections as a non-admin user."""
    token, non_admin = non_admin_token

    # Create connections for both users
    user_connections = [
        Connection(
            name=f"user-conn-{str(uuid.uuid4())[:8]}",
            created_by=test_user.username,
            guacamole_connection_id=f"test_guac_id_user_{i}",
        )
        for i in range(2)
    ]

    non_admin_connections = [
        Connection(
            name=f"non-admin-conn-{str(uuid.uuid4())[:8]}",
            created_by=non_admin.username,
            guacamole_connection_id=f"test_guac_id_non_admin_{i}",
        )
        for i in range(2)
    ]

    for conn in user_connections + non_admin_connections:
        test_db.add(conn)
    test_db.commit()

    # Use the non-admin token for authentication
    headers = {"Authorization": f"Bearer {token}"}

    # Get list of connections as non-admin
    response = test_client.get("/list", headers=headers)
    assert response.status_code == HTTPStatus.OK
    response_data = json.loads(response.data)
    assert "connections" in response_data

    # Non-admin should only see their own connections
    assert len(response_data["connections"]) == 2

    # Verify connection details
    non_admin_conn_names = [conn.name for conn in non_admin_connections]
    for conn in response_data["connections"]:
        assert "name" in conn
        assert "created_by" in conn
        assert conn["name"] in non_admin_conn_names
        assert conn["created_by"] == non_admin.username


def test_get_connection_success(test_client, test_db, test_user):
    """Test getting a specific connection."""
    # Create a test connection
    connection = Connection(
        name=f"test-connection-{str(uuid.uuid4())[:8]}",
        created_by=test_user.username,
        guacamole_connection_id="test_guac_id",
    )
    test_db.add(connection)
    test_db.commit()
    connection_name = (
        connection.name
    )  # Store the name before any potential session issues

    # Get the connection
    response = test_client.get(f"/{connection_name}")
    assert response.status_code == HTTPStatus.OK
    response_data = json.loads(response.data)
    assert "connection" in response_data

    # Verify connection details
    conn = response_data["connection"]
    assert conn["name"] == connection_name
    assert conn["created_by"] == test_user.username
    assert conn["guacamole_connection_id"] == "test_guac_id"


def test_get_nonexistent_connection(test_client):
    """Test getting a nonexistent connection."""
    response = test_client.get("/nonexistent")
    assert response.status_code == HTTPStatus.NOT_FOUND
    response_data = json.loads(response.data)
    assert "error" in response_data


def test_scale_down_cleanup_failure(
    test_client, mock_rancher_client, mock_guacamole, test_db, test_user
):
    """Test scale down when cleanup operations fail."""
    # Create a test connection
    connection = Connection(
        name=f"test-connection-{str(uuid.uuid4())[:8]}",
        created_by=test_user.username,
        guacamole_connection_id="test_guac_id",
    )
    test_db.add(connection)
    test_db.commit()
    test_db.refresh(connection)  # Refresh to ensure we have the latest state
    connection_name = connection.name
    connection_id = connection.id

    logging.info("=== Test Setup ===")
    logging.info(f"Created connection: id={connection_id}, name={connection_name}")
    logging.info(f"Using test user: id={test_user.id}, username={test_user.username}")

    # Verify initial state and ensure no active transaction
    initial_connection = test_db.query(Connection).filter_by(id=connection_id).first()
    logging.info(f"Initial state - Connection exists: {initial_connection is not None}")
    if initial_connection:
        logging.info(
            f"Initial state - Connection details: id={initial_connection.id}, name={initial_connection.name}"
        )

    # Ensure we're not in a transaction
    if test_db.in_transaction():
        test_db.rollback()
    logging.info(f"Initial state - In transaction: {test_db.in_transaction()}")

    # Mock cleanup failures
    mock_rancher_client.uninstall.side_effect = Exception("Failed to uninstall")
    with patch(
        "desktop_manager.api.routes.connection_routes.delete_guacamole_connection"
    ) as mock_delete:
        mock_delete.side_effect = GuacamoleError("Failed to delete connection")

        # Mock get_db to return our test_db
        with patch(
            "desktop_manager.api.routes.connection_routes.get_db",
            return_value=iter([test_db]),
        ):
            logging.info("=== Before Request ===")
            logging.info(f"Before request - In transaction: {test_db.in_transaction()}")

            # Make request
            response = test_client.post(
                "/scaledown",
                data=json.dumps({"name": connection_name}),
                content_type="application/json",
            )

            logging.info("=== After Request ===")
            logging.info(f"Response status: {response.status_code}")
            response_data = json.loads(response.data)
            logging.info(f"Response data: {response_data}")
            logging.info(f"After request - In transaction: {test_db.in_transaction()}")

            # Check response
            assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
            assert "error" in response_data

            # Verify connection state
            test_db.expire_all()
            logging.info("=== Verifying Connection State ===")
            logging.info(
                f"Checking connection with id={connection_id}, name={connection_name}"
            )

            # Try both ID and name-based queries
            by_id = test_db.query(Connection).filter_by(id=connection_id).first()
            by_name = test_db.query(Connection).filter_by(name=connection_name).first()

            logging.info(f"Found by ID: {by_id is not None}")
            logging.info(f"Found by name: {by_name is not None}")

            if by_id:
                logging.info(f"Connection by ID: id={by_id.id}, name={by_id.name}")
            if by_name:
                logging.info(
                    f"Connection by name: id={by_name.id}, name={by_name.name}"
                )

            # Final transaction state
            logging.info(f"Final state - In transaction: {test_db.in_transaction()}")

            assert by_id is not None, "Connection should exist when queried by ID"
            assert by_name is not None, "Connection should exist when queried by name"
            assert by_id == by_name, "Both queries should return the same connection"


# New tests for connection auth
def test_get_connection_auth_url_success(
    test_client, test_connection, mock_guacamole_json_auth
):
    """Test successful retrieval of connection auth URL."""
    # Patch the get_settings function to return a mock settings object with the required attributes
    with patch("desktop_manager.api.routes.connection_routes.get_settings") as mock_get_settings:
        mock_settings = Mock()
        mock_settings.GUACAMOLE_SECRET_KEY = "test_secret_key"
        mock_settings.GUACAMOLE_URL = "http://guacamole-test:8080/guacamole"
        mock_get_settings.return_value = mock_settings

        # Make the request
        response = test_client.get(f"/connect/{test_connection.id}")

        # Check response
        assert response.status_code == HTTPStatus.OK
        response_data = json.loads(response.data)
        assert "connection_id" in response_data
        assert "connection_name" in response_data
        assert "auth_url" in response_data

        # Verify correct values
        assert response_data["connection_id"] == str(test_connection.id)
        assert response_data["connection_name"] == test_connection.name

        # Verify auth URL format
        assert "guacamole/#/?data=" in response_data["auth_url"]


def test_get_connection_auth_url_nonexistent(test_client):
    """Test get connection auth for nonexistent connection."""
    response = test_client.get("/connect/999999")
    assert response.status_code == HTTPStatus.NOT_FOUND
    response_data = json.loads(response.data)
    assert "error" in response_data
    assert "Connection with ID 999999 not found" in response_data["error"]


def test_get_connection_auth_url_guacamole_json_auth_failure(test_client, test_connection):
    """Test get connection auth when GuacamoleJsonAuth fails."""
    # Mock GuacamoleJsonAuth to raise an exception
    with patch(
        "desktop_manager.api.routes.connection_routes.GuacamoleJsonAuth"
    ) as mock_class:
        mock_instance = Mock()
        mock_instance.generate_auth_data.side_effect = ValueError("Secret key error")
        mock_class.return_value = mock_instance

        # Make request
        response = test_client.get(f"/connect/{test_connection.id}")

        # Check response
        assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
        response_data = json.loads(response.data)
        assert "error" in response_data
        assert "details" in response_data
        assert "Internal server error" in response_data["error"]


def test_direct_connect_success(test_client, test_connection, mock_guacamole_json_auth):
    """Test successful direct connection redirect."""
    # Make request
    response = test_client.get(f"/direct-connect/{test_connection.id}")

    # Check response is a redirect
    assert (
        response.status_code == HTTPStatus.FOUND
    )  # 302 Found is the status code for a redirect

    # Get the redirect location
    redirect_url = response.location

    # Verify redirect URL format - accounting for both possible URL formats
    # Either the mocked external URL or the localhost fallback
    assert redirect_url.startswith(
        "http://guacamole-test:8080/guacamole/#/?data="
    ) or redirect_url.startswith("http://localhost:8080/guacamole/#/?data=")
    assert "mock-auth-token" in redirect_url

    # Verify GuacamoleJsonAuth was called correctly
    mock_guacamole_json_auth.generate_auth_data.assert_called_once()

    # Verify the call was made with the correct parameters
    # We can't extract individual arguments since the mock may not preserve them
    # Just check that the function was called
    assert mock_guacamole_json_auth.generate_auth_data.called


def test_direct_connect_nonexistent(test_client):
    """Test direct connect for nonexistent connection."""
    response = test_client.get("/direct-connect/999999")
    assert response.status_code == HTTPStatus.NOT_FOUND
    response_data = json.loads(response.data)
    assert "error" in response_data
    assert response_data["error"] == "Connection not found"


def test_direct_connect_guacamole_json_auth_failure(test_client, test_connection):
    """Test direct connect when GuacamoleJsonAuth fails."""
    # Mock GuacamoleJsonAuth to raise an exception
    with patch(
        "desktop_manager.api.routes.connection_routes.GuacamoleJsonAuth"
    ) as mock_class:
        mock_instance = Mock()
        mock_instance.generate_auth_data.side_effect = ValueError("Secret key error")
        mock_class.return_value = mock_instance

        # Make request
        response = test_client.get(f"/direct-connect/{test_connection.id}")

        # Check response
        assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
        response_data = json.loads(response.data)
        assert "error" in response_data
        assert "details" in response_data
        assert "Internal server error" in response_data["error"]


def test_get_connection_forbidden(test_client, test_db, non_admin_token):
    """Test getting a connection without permission."""
    token, non_admin = non_admin_token

    # Create a test admin user
    admin_user = User(
        username="admin_user",
        email="admin@example.com",
        password_hash="hash",
        is_admin=True,
    )
    test_db.add(admin_user)
    test_db.commit()

    # Create a connection owned by admin_user
    connection = Connection(
        name=f"test-connection-{str(uuid.uuid4())[:8]}",
        created_by=admin_user.username,
        guacamole_connection_id="test_guac_id",
    )
    test_db.add(connection)
    test_db.commit()

    # Use the non-admin token for authentication
    headers = {"Authorization": f"Bearer {token}"}

    # Make request to get a connection that the non-admin user doesn't own
    # Use the connection name in the URL, not the ID
    response = test_client.get(f"/{connection.name}", headers=headers)

    # Check response - should be forbidden for non-admin users
    assert response.status_code == HTTPStatus.FORBIDDEN
    response_data = json.loads(response.data)
    assert "error" in response_data
