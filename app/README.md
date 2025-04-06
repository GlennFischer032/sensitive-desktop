# Desktop Manager Frontend

A Flask-based web application that serves as the frontend interface for the Desktop Manager solution, integrated with Apache Guacamole for remote desktop access.

## Project Structure

```
app/
├── app.py                 # Main application entry point
├── __init__.py           # Application factory and initialization
├── Dockerfile            # Container configuration
├── pyproject.toml        # Project dependencies and metadata
├── uv.lock              # Dependency lock file
├── auth/                # Authentication related modules
├── config/              # Configuration modules
├── connections/         # Remote desktop connection handling
├── middleware/          # Custom Flask middleware
├── static/              # Static assets (CSS, JS, images)
├── templates/           # Jinja2 HTML templates
├── users/              # User management modules
└── utils/              # Utility functions and helpers
```

## Prerequisites

- Python 3.11+
- uv (Python package installer)
- Docker (for containerized deployment)
- Desktop Manager API service (must be running and accessible)
- Apache Guacamole server

## Development Setup

1. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/macOS
   # or
   .venv\Scripts\activate     # Windows
   ```

2. Install dependencies using uv:
   ```bash
   uv pip install -e .
   ```

3. Set up environment variables:
   ```bash
   export FLASK_APP=app.py
   export FLASK_ENV=development
   export SECRET_KEY=your-secret-key
   export API_URL=http://desktop-api:80
   ```

4. Run the development server:
   ```bash
   flask run
   ```

## Docker Deployment

Build the container:
```bash
docker build -t desktop-manager-frontend .
```

Run the container:
```bash
docker run -p 5000:5000 \
  -e SECRET_KEY=your-secret-key \
  -e API_URL=http://desktop-api:80 \
  desktop-manager-frontend
```

## Features

- User authentication and authorization
- Remote desktop connection management
- Integration with Apache Guacamole
- Responsive web interface
- Session management
- User management

## Configuration

Configuration is managed through environment variables and the config module:

- `SECRET_KEY`: Flask secret key for session management
- `API_URL`: URL of the Desktop Manager API service
- `FLASK_ENV`: Application environment (development/production)
- `FLASK_APP`: Application entry point

## Security

- CSRF protection enabled
- Secure session handling
- Input validation and sanitization
- XSS protection
- Secure headers middleware

## API Client

The application uses a structured API client to interact with the backend API. The client is organized as follows:

### Client Structure

- `BaseClient`: Base class that handles common functionality like making HTTP requests, error handling, etc.
- `AuthClient`: Handles authentication-related API requests (login, logout, token validation)
- `ConnectionsClient`: Handles connection-related API requests (listing, adding, deleting connections)
- `UsersClient`: Handles user-related API requests (listing, adding, deleting users)
- `ClientFactory`: Factory class to easily access all clients

### Using the Client

To use the client in your code:

```python
from clients.factory import client_factory

# Authentication
auth_client = client_factory.get_auth_client()
data, status_code = auth_client.login(username, password)

# Connections
connections_client = client_factory.get_connections_client()
connections = connections_client.list_connections()
connections_client.add_connection("new-connection")
connections_client.delete_connection("connection-name")

# Users
users_client = client_factory.get_users_client()
users = users_client.list_users()
users_client.add_user(username, password, is_admin=False)
users_client.delete_user(username)
```

### Error Handling

The client uses a custom `APIError` exception class for error handling:

```python
from clients.base import APIError

try:
    connections = connections_client.list_connections()
except APIError as e:
    # Access error details
    print(f"Error: {e.message}, Status: {e.status_code}")
    if e.details:
        print(f"Details: {e.details}")
except Exception as e:
    # Handle other exceptions
    print(f"Unexpected error: {str(e)}")
```
