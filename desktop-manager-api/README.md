# Desktop Manager API

A Flask-based REST API service that manages remote desktop connections through Apache Guacamole and integrates with Rancher for container orchestration.

## Project Structure

```
desktop-manager-api/
├── src/                  # Source code directory
├── Dockerfile           # Container configuration
├── pyproject.toml       # Project dependencies and metadata
├── uv.lock             # Dependency lock file
├── migrate.py          # Database migration script
├── healthcheck.sh      # Container health check script
├── init.sql            # Initial database setup
├── guacamole-init.sql  # Guacamole schema initialization
└── guacamole-init-users.sql  # Guacamole user initialization
```

## Prerequisites

- Python 3.11+
- uv (Python package installer)
- Docker (for containerized deployment)
- MySQL database
- Apache Guacamole server
- Rancher API access

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
   export FLASK_APP=desktop_manager.main
   export FLASK_ENV=development
   export SECRET_KEY=your-secret-key
   export MYSQL_HOST=localhost
   export MYSQL_PORT=3306
   export MYSQL_DATABASE=desktop_manager
   export MYSQL_USER=your-user
   export MYSQL_PASSWORD=your-password
   export GUACAMOLE_API_URL=http://guacamole:8080/guacamole/api
   export GUACAMOLE_USERNAME=guacadmin
   export GUACAMOLE_PASSWORD=your-password
   export RANCHER_API_URL=https://rancher.example.com
   export RANCHER_API_TOKEN=your-token
   export RANCHER_CLUSTER_ID=your-cluster-id
   export RANCHER_REPO_NAME=your-repo
   ```

4. Initialize the database:
   ```bash
   python migrate.py
   ```

5. Run the development server:
   ```bash
   flask run
   ```

## Docker Deployment

Build the container:
```bash
docker build -t desktop-manager-api .
```

Run the container:
```bash
docker run -p 5000:5000 \
  -e SECRET_KEY=your-secret-key \
  -e MYSQL_HOST=mysql \
  -e MYSQL_PORT=3306 \
  -e MYSQL_DATABASE=desktop_manager \
  -e MYSQL_USER=your-user \
  -e MYSQL_PASSWORD=your-password \
  -e GUACAMOLE_API_URL=http://guacamole:8080/guacamole/api \
  -e GUACAMOLE_USERNAME=guacadmin \
  -e GUACAMOLE_PASSWORD=your-password \
  -e RANCHER_API_URL=https://rancher.example.com \
  -e RANCHER_API_TOKEN=your-token \
  -e RANCHER_CLUSTER_ID=your-cluster-id \
  -e RANCHER_REPO_NAME=your-repo \
  desktop-manager-api
```

## Features

- RESTful API endpoints for desktop connection management
- User authentication and authorization
- Integration with Apache Guacamole for remote desktop access
- Integration with Rancher for container orchestration
- Database migrations and schema management
- Health check endpoints

## Configuration

Configuration is managed through environment variables:

### Database Configuration
- `MYSQL_HOST`: Database host
- `MYSQL_PORT`: Database port
- `MYSQL_DATABASE`: Database name
- `MYSQL_USER`: Database user
- `MYSQL_PASSWORD`: Database password

### Guacamole Configuration
- `GUACAMOLE_API_URL`: Guacamole API endpoint
- `GUACAMOLE_USERNAME`: Guacamole admin username
- `GUACAMOLE_PASSWORD`: Guacamole admin password

### Rancher Configuration
- `RANCHER_API_URL`: Rancher API endpoint
- `RANCHER_API_TOKEN`: Rancher API token
- `RANCHER_CLUSTER_ID`: Target cluster ID
- `RANCHER_REPO_NAME`: Repository name

### Application Configuration
- `SECRET_KEY`: Application secret key
- `FLASK_ENV`: Application environment (development/production)
- `FLASK_APP`: Application entry point

## Database Management

The application uses MySQL for data storage. Database schema and migrations are managed through:
- `migrate.py`: Database migration script
- `init.sql`: Initial schema setup
- `guacamole-init.sql`: Guacamole schema initialization
- `guacamole-init-users.sql`: Guacamole user initialization

## Security

- Token-based authentication
- Role-based access control
- Input validation and sanitization
- SQL injection protection
- Secure password hashing
- Rate limiting
- Secure headers