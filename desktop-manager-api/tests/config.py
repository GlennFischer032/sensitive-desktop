"""Test configuration and constants."""

# Test user data
TEST_USER = {
    "username": "test_user",
    "email": "test@example.com",
    "password": "Test@123",
    "organization": "Test Org",
    "sub": "test_user_sub_123",
}

TEST_ADMIN = {
    "username": "test_admin",
    "email": "admin@example.com",
    "password": "Admin@123",
    "organization": "Admin Org",
    "is_admin": True,
    "sub": "test_admin_sub_456",
}

# Test connection data
TEST_CONNECTION = {
    "name": "test_connection",
    "guacamole_connection_id": "test_guac_conn_1",
}

# Test desktop data
TEST_DESKTOP = {
    "name": "test_desktop",
    "connection_id": "test_conn_1",
    "ip_address": "192.168.1.100",
    "vnc_password": "test_vnc_pass",
}

# OIDC test data
TEST_OIDC = {
    "sub": "test_sub_123",
    "given_name": "Test",
    "family_name": "User",
    "email": "test.user@example.com",
    "email_verified": True,
    "locale": "en",
}

# Test tokens
TEST_ACCESS_TOKEN = "test_access_token"
TEST_REFRESH_TOKEN = "test_refresh_token"

# Guacamole test data
TEST_GUACAMOLE = {
    "auth_token": "test_guac_token",
    "username": "test_guac_user",
    "connection_id": "test_guac_conn",
}
