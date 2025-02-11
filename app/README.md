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
   export GUACAMOLE_URL=http://guacamole:8080/guacamole
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
  -e GUACAMOLE_URL=http://guacamole:8080/guacamole \
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
- `GUACAMOLE_URL`: URL of the Guacamole service
- `FLASK_ENV`: Application environment (development/production)
- `FLASK_APP`: Application entry point

## Security

- CSRF protection enabled
- Secure session handling
- Input validation and sanitization
- XSS protection
- Secure headers middleware