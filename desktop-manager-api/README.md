# Desktop Manager API

<!-- Optional: Add badges here -->

## Overview

This project provides the backend RESTful API for the Desktop Manager system. It handles business logic, data persistence, authentication, and communication with external services like Guacamole to support remote desktop access.

The API serves as the central component of the system, coordinating between:
- Frontend web application (`app/` directory in the project root)
- PostgreSQL database for persistent storage
- Guacamole for remote desktop protocol handling
- Storage management for persistent user data

This API is designed to work as part of a complete system deployed via the Helm chart in the `guacamole-helm` directory. In development, it runs as part of the Docker Compose setup defined in the project root.

## Features

-   **RESTful API:** Provides endpoints for managing system resources.
-   **Database Interaction:** Uses SQLAlchemy to interact with a PostgreSQL database.
-   **Authentication:**
    -   Supports JWT-based authentication using PyJWT.
    -   Uses Python-Jose with cryptography for enhanced security.
    -   Password hashing via Passlib with bcrypt.
    -   Handles user sessions and authorization.
-   **Guacamole Integration:** Manages Guacamole connections, users, and configurations.
-   **Storage Management:** Handles Persistent Volume Claims (PVCs) for user storage.
-   **Service Layer:** Business logic is encapsulated within services.
-   **Data Validation:** Uses Pydantic for request/response validation.
-   **Security:** Includes CORS protection and secure password handling.
-   **Containerization:** Dockerfile for building and running the API in a container.
-   **Testing:** Comprehensive test suite using Pytest.
-   **Code Quality:** Extensive linting and formatting enforced using Ruff and pre-commit hooks.

## Tech Stack

-   **Backend:** Python 3.11+, Flask
-   **Web Server:** Gunicorn (production), Flask development server (debug)
-   **Database:** PostgreSQL
-   **ORM:** SQLAlchemy
-   **Authentication:** Python-Jose with cryptography, Passlib with bcrypt, PyJWT, PyCryptodome (for Guacamole JSON auth)
-   **API Interaction:** Requests
-   **Data Validation:** Pydantic, Pydantic-Settings
-   **Security Libraries:** Flask-Cors
-   **Testing:** Pytest, pytest-cov, pytest-mock, pytest-asyncio, pytest-env, fakeredis, responses, freezegun, SQLAlchemy-Utils
-   **Linting/Formatting:** Ruff, pre-commit
-   **Containerization:** Docker
-   **Dependency Management:** uv, pip, setuptools

## Directory Structure

```
desktop-manager-api/
├── src/             # Main application code
│   ├── __init__.py
│   ├── main.py      # Flask app factory and entry point
│   ├── routes/      # API route definitions (blueprints)
│   ├── services/    # Business logic layer
│   ├── schemas/     # Pydantic schemas for data validation/serialization
│   ├── database/    # Database models, session management, initialization
│   ├── clients/     # Clients for external services (e.g., Guacamole, Kubernetes)
│   ├── config/      # Configuration loading
│   ├── core/        # Core components (e.g., security)
│   └── utils/       # Utility functions
├── tests/           # Pytest test suite
├── .pre-commit-config.yaml # Pre-commit hook configurations
├── Dockerfile       # Docker configuration for building the API image
├── pyproject.toml   # Project metadata, dependencies, tool configurations
├── uv.lock          # Pinned Python dependencies
├── format_code.sh   # Helper script to run formatting tools
├── healthcheck.sh   # Script used for Docker healthcheck
├── run_tests.sh     # Script to run the test suite
└── ... (other config/cache files)
```

## Database Setup

-   The application requires a **PostgreSQL** database.
-   Database connection details are configured via environment variables (see `Environment Variables` section).
-   **Initialization:**
    -   The database schema is automatically created during application startup via the `initialize_db()` function in `src/database/core/session.py`.
    -   This function calls `Base.metadata.create_all()` to create all tables defined in the SQLAlchemy models if they don't already exist.
    -   No manual database initialization is required when running with Docker Compose, as the API container will create the necessary tables on startup.
    -   If you need to reset the database, you can simply delete the PostgreSQL data volume and restart the containers.

## Prerequisites

Before you begin, ensure you have the following installed:

-   **Docker & Docker Compose:** Required for running the local development environment. The project uses Docker Compose to orchestrate multiple services.
-   **Python:** Version 3.11 or higher for local development, running tests, and pre-commit hooks.
-   **Git:** For version control and pre-commit hook integration.
-   **pre-commit:** For running code quality checks before committing changes.
-   **kubectl & Helm:** (Optional) Required only for deploying to a Kubernetes cluster.

For local development that doesn't involve changing the API itself, you might only need Docker and Docker Compose, as the application can run entirely in containers.

## Installation

These steps are for setting up the local development environment for working on the Desktop Manager API.

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd <repository-root>
    ```

2.  **Install pre-commit hooks:**
    ```bash
    # Install hooks for the entire project
    ./install_pre_commit.sh

    # Or just for the API component
    cd desktop-manager-api
    pre-commit install
    ```

3.  **Create a virtual environment** (Optional, for running tests or tools locally):
    ```bash
    cd desktop-manager-api
    python -m venv .venv
    source .venv/bin/activate  # On Windows use `.venv\Scripts\activate`
    pip install -e .
    ```

4.  **Set up environment variables:**
    Create a `.env` file in the project root with required environment variables (see `Environment Variables` section).

5.  **Start the development environment:**
    ```bash
    # From the project root
    docker-compose up -d
    ```

This will start the API, PostgreSQL, Guacamole, and frontend services. The API will be accessible at http://localhost:5000 and the frontend at http://localhost:5001.

## Environment Variables

The API relies heavily on environment variables for configuration. When running via the root `docker-compose.yaml`, these are set within the compose file itself, often referencing a `.env` file in the project root.

Key variables for this API service include:
```dotenv
# --- Database Settings --- #
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DATABASE=desktop_manager
POSTGRES_USER=guacamole_user
POSTGRES_PASSWORD=your_db_password

# --- Application Settings --- #
SECRET_KEY=your_strong_random_secret_key  # Used for Flask sessions, JWT signing
LOG_LEVEL=INFO  # Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
ADMIN_OIDC_SUB=your_admin_oidc_subject  # OIDC subject claim for the default admin user

# --- Guacamole Settings --- #
GUACAMOLE_URL=http://guacamole:8080/guacamole  # Internal URL for API to reach Guacamole
GUACAMOLE_JSON_SECRET_KEY=your_guacamole_json_auth_secret  # If using Guacamole JSON auth extension
GUACAMOLE_SECRET_KEY=your_guacamole_secret_key
EXTERNAL_GUACAMOLE_URL=http://localhost:8080/guacamole  # External URL used in frontend redirects

# --- OIDC Settings --- #
OIDC_PROVIDER_URL=https://login.e-infra.cz/oidc
OIDC_CLIENT_ID=your_oidc_client_id
OIDC_CLIENT_SECRET=your_oidc_client_secret
OIDC_CALLBACK_URL=http://localhost:5001/auth/oidc/callback  # Frontend callback
FRONTEND_URL=http://localhost:5001  # URL of the frontend application

# --- Rancher/Kubernetes Settings --- #
RANCHER_API_TOKEN=your_rancher_token
RANCHER_API_URL=your_rancher_api_url
RANCHER_CLUSTER_ID=your_cluster_id
RANCHER_CLUSTER_NAME=kuba-cluster
RANCHER_PROJECT_ID=your_project_id
RANCHER_REPO_NAME=your_repo_name
NAMESPACE=default

# --- Desktop Settings --- #
DESKTOP_IMAGE=cerit.io/desktops/ubuntu-xfce:22.04-user

# --- CORS Settings --- #
CORS_ALLOWED_ORIGINS=http://localhost:5001  # Comma-separated list of allowed origins
```
*Note:* Refer to `src/config/settings.py` for defaults and the root `docker-compose.yaml` for the definitive development setup.

## Running the API (Local Development)

This API service is designed to be run as part of a complete system using Docker Compose. It requires several services defined in the root `docker-compose.yaml`:

- **PostgreSQL**: For data persistence
- **Guacamole and Guacd**: For remote desktop capabilities
- **Redis**: Used by the frontend for session management
- **Desktop Frontend**: The web frontend that consumes this API

The recommended way to run the full system for development is:

1.  Navigate to the project root directory (containing `docker-compose.yaml`).
2.  Ensure you have a `.env` file with all required environment variables defined.
3.  Start all services:
    ```bash
    docker-compose up -d
    ```
4.  The API service will be accessible at:
    - Internally (to other containers): `http://desktop-api:5000`
    - Externally: `http://localhost:5000`
    - Debug port: `5679` (for connecting debuggers)

For debugging, the API container includes a debug port (5679) and mounts the source code as a volume to enable live code reloading.

## Running with Docker

Docker Compose is the primary way to run this API locally for development, alongside its dependencies.

The `desktop-manager-api/Dockerfile` defines how to build the image, and the `docker-compose.yaml` in the project root orchestrates running this service with its dependencies.

The docker-compose.yaml includes:
-   Build configuration with `FLASK_DEBUG=1` for development mode
-   Service dependencies (PostgreSQL, Guacamole, Guacd, Redis)
-   Network configuration via the `desktop-network` bridge network
-   Volume mounts for source code (`./desktop-manager-api/src:/app/src`)
-   Environment variable configuration
-   Healthchecks for service readiness
-   Restart policies

To build or run specific services:
```bash
# Build all services
docker-compose build

# Build only the API service
docker-compose build desktop-api

# Start only the API and its direct dependencies
docker-compose up -d postgres guacd guacamole desktop-api

# View logs for the API service
docker-compose logs -f desktop-api

# Restart the API service
docker-compose restart desktop-api
```

## Running Tests

The project has a comprehensive test suite organized into unit and functional tests.

### Test Types

- **Unit Tests** (`tests/unit/`): Focus on testing small components in isolation (models, utilities, services)
- **Functional Tests** (`tests/functional/`): Focus on testing API endpoints (HTTP methods, validation, responses)

### Running Tests Locally

You have multiple options for running tests:

```bash
# Run all tests with coverage
python -m pytest --cov=desktop_manager --cov-report=term-missing

# Run only unit tests
python -m pytest tests/unit/

# Run only functional tests
python -m pytest tests/functional/

# Run a specific test file
python -m pytest tests/unit/test_models.py
```

### Using the Provided Script

A helper script is available to run tests with pre-commit hooks:

```bash
./run_tests.sh
```

This script runs pre-commit hooks on all files and then executes the test suite with coverage reporting.

### Running Tests in Docker

You can also run tests within the Docker container:

```bash
docker-compose run --rm desktop-api python -m pytest
```

Refer to `tests/README.md` and `pyproject.toml` (`[tool.pytest.ini_options]`) for more details on test configuration.

## Linting and Formatting

This project uses `pre-commit` with `Ruff` to enforce code style and quality. The pre-commit configuration is defined in `.pre-commit-config.yaml`.

### Pre-commit Hooks

The pre-commit configuration includes:
- **Ruff**: For linting Python code with `--fix` and `--unsafe-fixes` arguments
- **Ruff Format**: For code formatting
- **Standard pre-commit hooks**: Checking for trailing whitespace, YAML validity, file size, etc.
- **Pytest**: Runs basic tests during pre-commit and coverage tests during pre-push

### Running Pre-commit

-   **Installation:** Set up pre-commit hooks with:
    ```bash
    pre-commit install
    ```

-   **Manual Checks:** Run checks on all files:
    ```bash
    # Run locally
    pre-commit run --all-files

    # Or run within the Docker container
    docker-compose run --rm desktop-api pre-commit run --all-files
    ```

-   **Manual Formatting:** Use the helper script to run Ruff formatting and checking:
    ```bash
    # Run locally
    ./format_code.sh

    # Or run within the Docker container
    docker-compose run --rm desktop-api /bin/bash -c "./format_code.sh"
    ```

### Project-wide Pre-commit Setup

There's also a root-level `.pre-commit-config.yaml` file in the project root directory. This configuration runs the pre-commit hooks for all services in the project, including both the desktop-manager-api and the app.

For installing pre-commit hooks at the project level, use:
```bash
./install_pre_commit.sh
```

## Deployment

The primary deployment strategy for this API and the entire Desktop Manager system is using **Kubernetes with Helm**.

### CI/CD Pipeline

The project includes a GitLab CI/CD pipeline (`.gitlab-ci.yml` in the project root) that:

1. Runs pre-commit hooks and tests during the lint stage
2. Builds Docker images for all components using Kaniko
3. Pushes the images to the GitLab container registry with both `latest` and timestamp-based tags

The pipeline is configured to build images only when changes are made to their respective directories.

### Helm Deployment

The `guacamole-helm` directory in the project root contains the Helm chart for deploying the entire Desktop Manager system to Kubernetes:

- `Chart.yaml`: Basic chart metadata
- `values.yaml`: Default configuration values
- `values.local.yaml`: Local development configuration overrides
- `templates/`: Kubernetes manifest templates
- `generate-secrets.py`: Script to generate required secrets

To deploy the application to a Kubernetes cluster:

1. Ensure you have Helm installed and configured with access to your cluster
2. Generate the required secrets with `generate-secrets.py`
3. Deploy the chart with the appropriate values file:

   ```bash
   cd guacamole-helm
   helm install desktop-manager . -f values.yaml
   ```

4. For local/development deployment, use the local values:

   ```bash
   helm install desktop-manager . -f values.local.yaml
   ```

### Deploying Individual Components

The Dockerfile in the `desktop-manager-api` directory can be used to build a production-ready image for standalone deployment. However, the recommended approach is to deploy the entire system using the Helm chart to ensure proper integration and configuration.

For more information about the Helm chart and deployment options, refer to the `guacamole-helm/README.md` file in the project root.

## API Endpoints Overview

The API exposes several sets of endpoints, organized by Flask Blueprints:

-   **/api/connections/** (`connection_routes.py`):
    -   Manages user connections related to Guacamole (CRUD operations, details, parameters).
-   **/api/desktop-config/** (`desktop_configuration_routes.py`):
    -   Handles configuration settings specific to user desktops or sessions.
-   **/api/users/** (`user_routes.py`):
    -   Manages user information within the Desktop Manager system.
-   **/api/storage-pvcs/** (`storage_pvc_routes.py`):
    -   Manages Persistent Volume Claims (PVCs) related to user storage.
-   **/api/auth/oidc/** (`oidc_routes.py`):
    -   Handles authentication flows.
-   **/api/token/** (`token_routes.py`):
    -   Provides endpoints for obtaining and refreshing API tokens.
-   **/api/health** (`main.py`):
    -   A simple health check endpoint to verify API and database connectivity.

*Note: This is a high-level overview. Refer to the route definitions in `src/routes/` for specific endpoints, methods, request/response formats, and required permissions.*

## Authentication/Authorization

-   **Primary Authentication:** The API uses JWT tokens for authentication.
    -   Tokens are issued via the `/api/token/` endpoints.
    -   Authentication is managed through the token_routes.py module.
-   **Admin User:** A default administrative user is automatically created during initialization as defined in the `main.py` file using the UserService.
-   **API Tokens (JWT):** The `/api/token/` endpoints provide functionality to obtain and refresh JWT tokens used for authenticating API requests.
-   **Authorization:** Endpoint access control is implemented within the route handlers or through decorators that check user roles and permissions based on the authenticated user token.
-   **Guacamole Integration:** The API manages user authentication within Guacamole, creating and associating users. It uses the credentials configured in the environment variables to interact with the Guacamole API.
