"""Mock implementations for testing."""

import logging
from typing import Dict, List, Any, Tuple, Optional
from werkzeug.security import generate_password_hash
from datetime import datetime

from desktop_manager.api.models.user import User
from desktop_manager.core.exceptions import APIError


class MockDatabaseClient:
    """Mock database client for testing."""

    def __init__(self, session=None):
        """Initialize the mock database client.

        Args:
            session: SQLAlchemy session for direct DB operations
        """
        self.session = session
        self.logger = logging.getLogger("MockDatabaseClient")

    def execute_query(self, query, params=None):
        """Mock execute_query method."""
        if params is None:
            params = {}

        self.logger.info(f"Mock executing query: {query} with params: {params}")

        if "SELECT * FROM users WHERE id = :user_id" in query:
            user_id = params.get("user_id")
            if user_id:
                if user_id == 2:
                    is_admin = False
                    username = f"test_user_{user_id:08x}"
                else:
                    is_admin = bool(user_id % 2 == 1)

                    if "username" in params and params["username"] and (
                        "admin" in params["username"]
                    ):
                        is_admin = True

                    if is_admin:
                        username = f"test_admin_{user_id:08x}"
                    else:
                        username = f"user{user_id}"

                self.logger.info(f"Returning mock user: id={user_id}, username={username}, is_admin={is_admin}")
                return [{"id": user_id, "username": username, "is_admin": is_admin}], 1
            return [], 0

        # Check if user exists by ID
        if "SELECT id FROM users WHERE username = :username" in query:
            username = params.get("username")
            if username == "testuser" or username.startswith("test_user_"):
                return [{"id": 1}], 1
            if username == "admin" or username.startswith("test_admin_"):
                return [{"id": 2}], 1
            # Nonexistent user for testing
            return [], 0

        # Check if user exists by username
        if "SELECT * FROM users WHERE username = :username" in query:
            username = params.get("username")
            if username == "testuser" or username.startswith("test_user_"):
                return [{"id": 1, "username": username, "password": "hashed_password", "is_admin": False}], 1
            if username == "admin" or username.startswith("test_admin_"):
                return [{"id": 2, "username": username, "password": "hashed_password", "is_admin": True}], 1
            # Nonexistent user for testing
            return [], 0

        # Check user exists by username or email
        if "SELECT username, email FROM users WHERE username = :username OR email = :email" in query:
            username = params.get("username")
            email = params.get("email")
            if username == "testuser" or email == "test@example.com":
                return [{"username": "testuser", "email": "test@example.com"}], 1
            # Nonexistent user for testing
            return [], 0

        # List all users
        if "SELECT id, username, email, is_admin" in query:
            # Return mock list of users
            return [
                {"id": 1, "username": "testuser", "email": "test@example.com", "is_admin": False, "created_at": None, "last_login": None},
                {"id": 2, "username": "admin", "email": "admin@example.com", "is_admin": True, "created_at": None, "last_login": None}
            ], 2

        # List all users with created_at and last_login
        if "SELECT id, username, email, is_admin, created_at, last_login" in query:
            # Return mock list of users with valid created_at
            current_time = datetime.now()
            return [
                {"id": 1, "username": "testuser", "email": "test@example.com", "is_admin": False, "created_at": current_time, "last_login": None},
                {"id": 2, "username": "admin", "email": "admin@example.com", "is_admin": True, "created_at": current_time, "last_login": None}
            ], 2

        # Check user authentication
        if "SELECT * FROM users WHERE username = :username" in query and "password" not in query:
            username = params.get("username")
            if username == "testuser" or username.startswith("test_user_"):
                return [
                    {
                        "id": 1,
                        "username": username,
                        "password": generate_password_hash("password123"),
                        "is_admin": False,
                    }
                ], 1
            elif username == "admin" or username.startswith("test_admin_"):
                return [
                    {
                        "id": 2,
                        "username": username,
                        "password": generate_password_hash("admin123"),
                        "is_admin": True,
                    }
                ], 1
            return [], 0

        # Handle authentication query
        if "SELECT * FROM users WHERE username = :username AND password = :password" in query:
            username = params.get("username")
            password = params.get("password")
            if username == "testuser" and password == "password123":
                return [{"id": 1, "username": "testuser", "is_admin": False}], 1
            elif username == "admin" and password == "admin123":
                return [{"id": 2, "username": "admin", "is_admin": True}], 1
            return [], 0

        # Handle insert queries
        if query.strip().upper().startswith("INSERT"):
            # For user creation
            if "INSERT INTO users" in query:
                return [{"id": 999}], 1
            # For other inserts
            return None, 1

        # Handle update queries
        if query.strip().upper().startswith("UPDATE"):
            # For any update operations
            return None, 1

        # Handle delete queries
        if query.strip().upper().startswith("DELETE"):
            # For any delete operations
            return None, 1

        # Log unhandled queries for debugging
        self.logger.info(f"Unhandled mock query: {query}")

        # Default fallback for any other query
        return [], 0

    def insert_values(self, table_name: str, values: Dict[str, Any]) -> int:
        """Mock insert operation.

        Returns a mock ID for the inserted record.
        """
        self.logger.info("Mock inserting into %s values: %s", table_name, values)
        return 1

    def execute_transaction(self, queries):
        """Mock transaction execution.

        Returns mock results for each query in the transaction.
        """
        results = []
        for query, params in queries:
            result, count = self.execute_query(query, params)
            results.append((result, count))
        return results
