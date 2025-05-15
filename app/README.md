# Desktop Frontend

## Overview

This project is the Flask-based web frontend for the Desktop Manager system. It serves two primary purposes:
1.  Provides a **user interface (UI)** for users to interact with the system's features.
2.  Acts as an **API proxy**, forwarding requests to the backend `desktop-manager-api` service. This is a crucial security measure, as the backend API itself should not be directly exposed.

The frontend is designed to be run as part of a larger system, typically orchestrated via Docker Compose for development and Kubernetes/Helm for production. Key aspects include robust security features (including session-based authentication), containerization via Docker, automated testing, and code quality checks.

## Features

-   **User Interface:** Web-based interface for interacting with the application's functionalities.
-   **Authentication:** Secure user login and session management.
-   **Connection Management:** Functionality to manage remote desktop connections.
-   **User Management:** Capabilities for managing user accounts and permissions.
-   **Configuration Management:** Interface for managing desktop configurations.
-   **Token Management:** Issuing and managing API tokens for internal service communication.
-   **Storage Interaction:** Interface for interacting with storage services.
-   **RESTful API Proxy:** Secure forwarding of API requests to the backend.
-   **Security:** Multiple security measures implemented:
    -   Security headers (Flask-Talisman)
    -   Rate limiting (Flask-Limiter)
    -   Input validation (Pydantic)
    -   Secure session management (Redis-backed sessions)
-   **API Documentation:** Integrated Swagger UI for exploring and testing API endpoints.
-   **Containerization:** Docker-based deployment with environment-specific configurations.
-   **Testing:** Comprehensive test suite using Pytest.
-   **Code Quality:** Linting and formatting enforced using Ruff, Black, isort, and pre-commit hooks.

## Tech Stack

-   **Backend:** Python 3.11+, Flask
-   **Web Server:** Gunicorn (production), Flask development server (debug)
-   **Session Management:** Redis (via Flask-Session)
-   **Templating:** Jinja2
-   **Frontend Styling:** SCSS/Sass (compiled to CSS)
-   **API Documentation:** Flasgger (Swagger UI)
-   **Data Validation:** Pydantic
-   **Security Libraries:** Flask-Cors, Flask-Session, Flask-Limiter, Flask-Talisman, PyJWT, python-jose
-   **Testing:** Pytest, pytest-cov, pytest-mock, pytest-flask, fakeredis
-   **Linting/Formatting:** Ruff, Black, isort, pre-commit
-   **Containerization:** Docker
-   **Dependency Management:** uv

## Directory Structure

```
app/
├── src/                  # Main application code
│   ├── __init__.py       # Application factory and initialization
│   ├── app.py            # Main application entry point
│   ├── clients/          # Client implementations for external services
│   ├── config/           # Application configuration files/classes
│   ├── middleware/       # Custom middleware components
│   ├── scss/             # SCSS source files
│   ├── scripts/          # Helper scripts
│   ├── services/         # Core application logic organized by feature
│   │   ├── auth/         # Authentication and authorization
│   │   ├── configurations/  # Desktop configuration management
│   │   ├── connections/  # Remote desktop connection management
│   │   ├── storage/      # Storage service integration
│   │   ├── tokens/       # Token management
│   │   └── users/        # User management
│   ├── static/           # Compiled static assets
│   ├── templates/        # Jinja2 HTML templates
│   └── utils/            # Utility functions and classes
├── tests/                # Test suite
│   ├── functional/       # Functional/integration tests
│   ├── unit/             # Unit tests
│   └── data/             # Test data fixtures
├── .pre-commit-config.yaml  # Pre-commit hook configuration
├── Dockerfile            # Docker build configuration
├── pyproject.toml        # Project metadata and tool configurations
└── uv.lock               # Pinned dependencies
```

## Prerequisites

Before you begin, ensure you have the following installed:

-   **Python:** Version 3.11 or higher.
-   **uv:** For Python package management (recommended over pip).
-   **Docker & Docker Compose:** Required for running the development environment.
-   **pre-commit:** For managing Git hooks.
-   **(Optional) Build Tools:** For local development outside of Docker, you might need C build tools (`gcc`, `make`).

## Installation

These steps are primarily for setting up the local environment for development. For running the entire system, refer to the `docker-compose.yaml` in the project root.

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd <repository-root>
    ```

2.  **Create and activate a virtual environment:** (Optional, for local development outside Docker)
    ```bash
    python -m venv .venv
    source .venv/bin/activate  # On Windows use `.venv\Scripts\activate`
    ```

3.  **Install dependencies:**
    ```bash
    # Using uv (recommended)
    uv pip install -e ".[dev,test]"

    # Or using pip
    pip install -e ".[dev,test]"
    ```

4.  **Environment Variables:**
    The application requires these key environment variables:
    ```dotenv
    # Mandatory: Generate a strong secret key
    SECRET_KEY='your_strong_random_secret_key'

    # Mandatory: URL for the backend API service
    API_URL='http://desktop-manager-api:5000' # Within Docker network

    # Mandatory: Connection URL for Redis
    REDIS_URL='redis://redis:6379/0' # Within Docker network

    # Set to "true" for development mode
    DEBUG='false'
    ```

5.  **Install pre-commit hooks:**
    ```bash
    pre-commit install
    ```

## Running the Application

This application is designed to be run as part of the larger system using Docker Compose:

1.  Navigate to the project root directory (containing `docker-compose.yaml`).
2.  Ensure you have a `.env` file with all required environment variables.
3.  Start all services:
    ```bash
    docker-compose up -d
    ```
4.  The frontend application should be accessible at `http://localhost:5001` (adjust port as needed based on docker-compose configuration).

For local development with live reloading:
```bash
# From the app directory, with environment variables set
export FLASK_APP=src/app.py
export FLASK_DEBUG=1
flask run
```

## Running with Docker

The `app/Dockerfile` supports both development and production environments:

- **Development Mode:**
  ```bash
  # Build with debug flag enabled
  docker build -t desktop-frontend:dev --build-arg FLASK_DEBUG=1 .

  # Run with mounted source code for live reloading
  docker run -p 5001:5000 -v $(pwd)/src:/app/src desktop-frontend:dev
  ```

- **Production Mode:**
  ```bash
  # Build production image
  docker build -t desktop-frontend:prod .

  # Run in production mode
  docker run -p 5001:5000 desktop-frontend:prod
  ```

For a complete development environment, use the docker-compose file in the project root.

## Running Tests


```bash
# Run all tests
pytest

# Run only unit tests
pytest tests/unit

# Run with coverage
pytest --cov=src
```

## Linting and Formatting

This project uses `pre-commit` with `Ruff` for code quality:

```bash
# Run all checks
pre-commit run --all-files

```

## Deployment

The recommended deployment method is using Kubernetes with Helm:

1. Build a production Docker image with appropriate environment variables.
2. Configure the Helm chart values for your environment.
3. Deploy using Helm:
   ```bash
   helm upgrade --install desktop-frontend ./helm/desktop-frontend -f values.yaml
   ```

For detailed deployment instructions, refer to the Helm chart documentation in the project repository.

## API Documentation

API documentation is accessible via Swagger UI at `/api/docs/` when the application is running.

Note that this is primarily documentation for the proxy endpoints that this frontend service provides as an interface to the backend API.
