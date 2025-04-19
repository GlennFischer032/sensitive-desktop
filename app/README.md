# Desktop Frontend

<!-- Optional: Add badges here -->

## Overview

This project is the Flask-based web frontend for the Desktop Manager system. It serves two primary purposes:
1.  Provides a **user interface (UI)** for users to interact with the system's features.
2.  Acts as an **API proxy**, forwarding requests to the backend `desktop-api` service. This is a crucial security measure, as the `desktop-api` itself should not be directly exposed.

The frontend is designed to be run as part of a larger system, typically orchestrated via Docker Compose for development and Kubernetes/Helm for production. Key aspects include robust security features (including OIDC authentication), containerization via Docker, automated testing, and code quality checks.

## Features

-   **User Interface:** Web-based interface for interacting with the application's functionalities.
-   **RESTful API:** Provides API endpoints for programmatic access and integration.
-   **Authentication:** Secure user login and session management.
-   **Connection Management:** Functionality to manage connections (details inferred from service name).
-   **User Management:** Capabilities for managing user accounts (e.g., adding/deleting users, potentially roles/permissions).
-   **Configuration Management:** Handling application or service configurations.
-   **Token Management:** Issuing and managing API tokens or similar credentials.
-   **Storage Interaction:** Interface for interacting with storage services.
-   **API Documentation:** Integrated Swagger UI for exploring and testing API endpoints (requires admin privileges).
-   **Security:** Includes measures like CSRF protection (Flask-Seasurf), security headers (Talisman), rate limiting, input validation, and secure password handling (Argon2).
-   **Containerization:** Dockerfile for building and running the application in a container.
-   **Testing:** Comprehensive test suite using Pytest.
-   **Code Quality:** Linting and formatting enforced using Ruff, Black, isort, and pre-commit hooks.

## Tech Stack

-   **Backend:** Python 3.11+, Flask
-   **Web Server:** Gunicorn (production), Flask development server (debug)
-   **Session Management:** Redis (via Flask-Session)
-   **Templating:** Jinja2 (implied by Flask usage and `templates/` directory)
-   **Frontend Styling:** SCSS/Sass (compiled to CSS)
-   **API Documentation:** Flasgger (Swagger UI)
-   **Data Validation:** Pydantic
-   **Security Libraries:** Flask-Cors, Flask-Session, Flask-Limiter, Flask-Talisman, Flask-Seasurf, Argon2-cffi, Bleach, PyJWT, python-jose
-   **Testing:** Pytest, pytest-cov, pytest-mock, pytest-flask, fakeredis
-   **Linting/Formatting:** Ruff, Black, isort, pre-commit
-   **Containerization:** Docker
-   **Dependency Management:** uv, pip, setuptools

## Directory Structure

```
app/
├── __init__.py           # Application factory and initialization
├── app.py                # Main application entry point (runs create_app)
├── clients/              # Client implementations for external services (e.g., Redis)
├── config/               # Application configuration files/classes
├── middleware/           # Custom middleware (e.g., authentication, security)
├── scss/                 # SCSS source files
├── scripts/              # Helper scripts (e.g., sass compilation, running tests)
├── services/             # Core application logic organized by feature (auth, users, etc.)
│   ├── auth/
│   ├── configurations/
│   ├── connections/
│   ├── storage/
│   ├── tokens/
│   └── users/
├── static/               # Compiled static assets (CSS, JS, images)
├── templates/            # Jinja2 HTML templates
├── tests/                # Application tests (unit, integration, functional)
├── utils/                # Utility functions and classes
├── .pre-commit-config.yaml # Pre-commit hook configurations
├── Dockerfile            # Docker configuration for building the application image
├── pyproject.toml        # Project metadata, dependencies, and tool configurations (ruff, pytest, etc.)
└──  uv.lock               # Pinned Python dependencies
```

## Prerequisites

Before you begin, ensure you have the following installed:

-   **Python:** Version 3.11 or higher.
-   **uv or pip:** For Python package management (`uv` is recommended).
-   **Docker & Docker Compose:** Required for running the local development environment.
-   **pre-commit:** For managing Git hooks.
-   **(Optional) Build Tools:** If installing `libsass` locally (not needed for Docker setup), you might need C build tools (`gcc`, `make`).

## Installation

These steps are primarily for setting up the local environment for development *on this specific frontend service*. For running the *entire system*, refer to the `docker-compose.yaml` in the project root.

1.  **Clone the repository:** (If you haven't already)
    ```bash
    git clone <your-repository-url>
    cd <repository-root>/app
    ```

2.  **Create and activate a virtual environment:** (Optional, if you need to run linters/tools locally outside Docker)
    ```bash
    python -m venv .venv
    source .venv/bin/activate  # On Windows use `.venv\Scripts\activate`
    ```

3.  **Install dependencies:** (Optional, needed for local pre-commit hooks or IDE integration)
    ```bash
    # Using uv (recommended)
    uv pip install -e ".[dev,test]"

    # Or using pip
    pip install -e ".[dev,test]"
    ```

4.  **Environment Variables:**
    The application relies heavily on environment variables for configuration. When running via the root `docker-compose.yaml`, these are set within the compose file itself, often referencing a `.env` file in the project root.

    Key variables for *this frontend service* include:
    ```dotenv
    # Mandatory: Generate a strong secret key (must match other services if shared)
    SECRET_KEY='your_strong_random_secret_key'

    # Mandatory: URL for the backend API service
    API_URL='http://desktop-api:5000' # Within Docker network

    # Mandatory: Connection URL for Redis
    REDIS_URL='redis://redis:6379/0' # Within Docker network

    # Mandatory: External URL for Guacamole (used for redirects/links)
    EXTERNAL_GUACAMOLE_URL='http://localhost:8080/guacamole' # Example, adjust port if needed

    # OIDC Configuration (Mandatory for OIDC login)
    OIDC_CLIENT_ID='your_oidc_client_id'
    OIDC_CLIENT_SECRET='your_oidc_client_secret'
    OIDC_PROVIDER_URL='https://your_oidc_provider.com/oidc'
    OIDC_REDIRECT_URI='http://localhost:5001/auth/oidc/callback' # Adjust host/port if needed

    # Set to "1" for development mode features
    FLASK_DEBUG='1'

    # Set to "1" to enable optional debug login form (for development only)
    DEBUG_LOGIN_ENABLED='0'
    ```
    *Note:* Refer to `app/config/config.py` for defaults and `docker-compose.yaml` in the project root for the definitive development setup.

5.  **Install pre-commit hooks:** (Run from within the `app` directory)
    ```bash
    pre-commit install
    ```

## Running the Application

This application is **not designed to be run standalone**. It requires the `desktop-api`, `redis`, and potentially other services defined in the root `docker-compose.yaml`.

The recommended way to run the full system for development is using Docker Compose from the **project root directory**:

1.  Navigate to the project root directory (the one containing `docker-compose.yaml`).
2.  Ensure you have a `.env` file in the root directory with all the required environment variables defined (see the `docker-compose.yaml` for needed variables like `POSTGRES_USER`, `SECRET_KEY`, etc.).
3.  Start all services:
    ```bash
    docker-compose up -d
    ```
4.  The frontend application should then be accessible at `http://localhost:5001` (based on the ports defined in `docker-compose.yaml`).

Running `flask run` or `gunicorn` directly within the `app` directory *without* the rest of the Docker Compose stack will likely result in errors.

## Running with Docker

As mentioned above, Docker (specifically Docker Compose) is the primary way to run the application locally for development.

The `app/Dockerfile` defines how to build the image for this specific frontend service. The `docker-compose.yaml` file in the **project root** orchestrates the building and running of this service along with all its dependencies (`desktop-api`, `redis`, `postgres`, `guacamole`, `guacd`).

Please refer to the `docker-compose.yaml` in the project root for details on:
-   Building the development image (usually includes `FLASK_DEBUG=1` build arg).
-   Service dependencies.
-   Network configuration.
-   Volume mounts for live code reloading during development.
-   Environment variable injection.

To build/run only this service (e.g., after changes), you can use compose commands from the root directory:
```bash
# Rebuild the frontend service image
docker-compose build desktop-frontend

# Stop and restart only the frontend service
docker-compose stop desktop-frontend
docker-compose up -d desktop-frontend
```

## Running Tests

**Running Locally (Requires local Python env setup):**
Use the helper script `app/scripts/run_tests.py`:
```bash
# Run all tests
python app/scripts/run_tests.py

# Run only unit tests
python app/scripts/run_tests.py --type unit

# Run all tests and generate a coverage report in the terminal
python app/scripts/run_tests.py --coverage

# Run all tests and generate an HTML coverage report (in `htmlcov/`)
python app/scripts/run_tests.py --coverage --html
```
Refer to `pyproject.toml` (`[tool.pytest.ini_options]`) for pytest configuration.

## Linting and Formatting

This project uses `pre-commit` with `Ruff` to enforce code style and quality.

-   **Automatic Checks:** Hooks run automatically when you commit changes (requires local pre-commit installation).
-   **Manual Checks:** Run checks on all files:
    ```bash
    # Run locally (requires pre-commit and Python env)
    pre-commit run --all-files

    # Or run within the Docker container
    docker-compose run --rm desktop-frontend pre-commit run --all-files
    ```
Configuration is in `.pre-commit-config.yaml` and `pyproject.toml` (`[tool.ruff]`).

## Deployment

The primary deployment strategy for this application and the entire Desktop Manager system is using **Kubernetes with Helm**.

While the `app/Dockerfile` can be used to build a production-ready image (by setting `FLASK_DEBUG=0` during build), the deployment process typically involves:

1.  Packaging the application along with its Kubernetes manifests into a Helm chart.
2.  Configuring environment-specific values (secrets, API URLs, resource limits, etc.) via Helm values files.
3.  Deploying the chart to a Kubernetes cluster using `helm install` or `helm upgrade`.

Refer to the Helm chart definition (if available in the repository) for specific deployment instructions and configuration options.

Running the application using `docker run` or Docker Compose in production is generally **not recommended** compared to a proper Kubernetes/Helm deployment.

## API Documentation

API documentation is automatically generated using Flasgger and is available via Swagger UI.

-   **Access:** Navigate to `/api/docs/` on the running application URL (e.g., `http://localhost:5000/api/docs/`).
-   **Authentication:** Access to the API documentation requires administrator privileges. You must be logged in as an admin user.

The following API blueprints are documented:
-   Authentication API
-   Connections API
-   Users API
-   Configurations API
-   Storage API
-   Tokens API
