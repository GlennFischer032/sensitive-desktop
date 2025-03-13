# Desktop Manager API Clients

This package provides a set of client classes for interacting with various components of the Desktop Manager system.

## Client Structure

The client architecture consists of the following components:

### BaseClient

The `BaseClient` class provides common functionality for all clients, including:

- HTTP request methods (GET, POST, PUT, DELETE)
- Error handling
- Logging

### GuacamoleClient

The `GuacamoleClient` class provides methods for interacting with Apache Guacamole, including:

- `login()`: Authenticate with Guacamole
- `create_user()`: Create a user in Guacamole
- `delete_user()`: Delete a user from Guacamole
- `update_user()`: Update a user's attributes in Guacamole
- `add_user_to_group()`: Add a user to a group in Guacamole
- `remove_user_from_group()`: Remove a user from a group in Guacamole
- `create_connection()`: Create a connection in Guacamole
- `delete_connection()`: Delete a connection from Guacamole
- `grant_permission()`: Grant permission to a user for a connection in Guacamole
- `grant_group_permission()`: Grant permission to a group for a connection in Guacamole

### RancherClient

The `RancherClient` class provides methods for managing Rancher deployments, including:

- `install()`: Install a Helm chart via Rancher API
- `uninstall()`: Uninstall a Helm chart via Rancher API
- `check_vnc_ready()`: Check if VNC server is ready
- `get_pod_ip()`: Get the IP address of a pod
- `list_releases()`: List Helm releases via Rancher API
- `get_release()`: Get a Helm release via Rancher API

### DatabaseClient

The `DatabaseClient` class provides methods for database operations, including:

- `execute_query()`: Execute a SQL query
- `get_connection_details()`: Get details for a connection
- `list_connections()`: List all connections
- `get_user_details()`: Get details for a user
- `list_users()`: List all users

## Client Factory

The `ClientFactory` class provides methods for getting client instances:

- `get_database_client()`: Get a DatabaseClient instance
- `get_guacamole_client()`: Get a GuacamoleClient instance
- `get_rancher_client()`: Get a RancherClient instance

## Using Clients

### Using GuacamoleClient

```python
from desktop_manager.clients import client_factory

# Get a GuacamoleClient instance
guacamole_client = client_factory.get_guacamole_client()

# Login to Guacamole
token = guacamole_client.login()

# Create a user
guacamole_client.create_user(token, "username", "password")

# Add user to group
guacamole_client.add_user_to_group(token, "username", "group_name")
```

### Using RancherClient

```python
from desktop_manager.clients import client_factory
from desktop_manager.core.rancher import DesktopValues

# Get a RancherClient instance
rancher_client = client_factory.get_rancher_client()

# Create desktop values
values = DesktopValues(desktop="desktop-image", name="connection-name", vnc_password="password")

# Install a Helm chart
rancher_client.install("connection-name", values)

# Check if VNC is ready
is_ready = rancher_client.check_vnc_ready("connection-name")

# Get pod IP
pod_ip = rancher_client.get_pod_ip("connection-name")

# Uninstall a Helm chart
rancher_client.uninstall("connection-name")
```

### Using DatabaseClient

```python
from desktop_manager.clients import client_factory

# Get a DatabaseClient instance
database_client = client_factory.get_database_client()

# Execute a query
rows, count = database_client.execute_query("SELECT * FROM users")

# Get connection details
connection = database_client.get_connection_details("connection_name")

# List connections
connections = database_client.list_connections()
```

## Error Handling

All clients use the `APIError` exception class for error handling:

```python
from desktop_manager.clients import APIError

try:
    guacamole_client.create_user("username", "password")
except APIError as e:
    print(f"Error: {e.message}, Status Code: {e.status_code}")
    if e.details:
        print(f"Details: {e.details}")
