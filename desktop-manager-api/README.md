# Desktop Manager API

<!-- Optional: Add badges here -->

## Overview

This project provides the backend RESTful API for the Desktop Manager system. It handles business logic, data persistence, authentication (including OIDC), and communication with external services like Guacamole and potentially Kubernetes.

This API is designed to be consumed primarily by the `desktop-frontend` service, which acts as a secure proxy. The API itself should generally not be exposed directly to the public internet.

## Features

-   **RESTful API:** Provides endpoints for managing system resources.
-   **Database Interaction:** Uses SQLAlchemy and SQLModel to interact with a PostgreSQL database.
-   **Authentication:**
    -   Supports OIDC-based authentication via `python-social-auth`.
    -   Handles user sessions and authorization.
    -   Integrates with Guacamole authentication mechanisms (PostgreSQL & potentially JSON auth).
-   **Guacamole Integration:** Manages Guacamole connections, users, and configurations within the database.
-   **Kubernetes Integration:** (Inferred from dependencies) Likely interacts with Kubernetes APIs for managing resources (e.g., related to desktop sessions).
-   **Service Layer:** Business logic is encapsulated within services.
-   **Data Validation:** Uses Pydantic for request/response validation (implied via schemas).
-   **Security:** Includes measures for CSRF protection, security headers (Talisman), rate limiting, password hashing (Argon2), and input sanitization (Bleach).
-   **Containerization:** Dockerfile for building and running the API in a container.
-   **Testing:** Test suite using Pytest.
-   **Code Quality:** Linting and formatting enforced using Ruff and pre-commit hooks.

## Tech Stack

-   **Backend:** Python 3.11+, Flask
-   **Web Server:** Gunicorn (production), Flask development server (debug)
-   **Database:** PostgreSQL
-   **ORM:** SQLAlchemy, SQLModel
-   **Authentication:** Python Social Auth (OIDC), PyJWT, Passlib/Argon2, PyCryptodome (for Guacamole JSON auth)
-   **API Interaction:** Requests
-   **Kubernetes Client:** Kubernetes Python Client
-   **Data Validation:** Pydantic
-   **Security Libraries:** Flask-Cors, Flask-Limiter, Flask-Talisman, Flask-Seasurf, Argon2-cffi, Bleach
-   **Testing:** Pytest, pytest-cov, pytest-mock, pytest-asyncio, responses, fakeredis
-   **Linting/Formatting:** Ruff, pre-commit
-   **Containerization:** Docker
-   **Dependency Management:** uv, pip, setuptools

## Directory Structure

```
desktop-manager-api/
├── src/
│   ├── desktop_manager/  # Main application package
│   │   ├── __init__.py
│   │   ├── main.py       # Flask app factory and entry point
│   │   ├── routes/       # API route definitions (blueprints)
│   │   ├── services/     # Business logic layer
│   │   ├── schemas/      # Pydantic schemas for data validation/serialization
│   │   ├── database/     # Database models, session management, initialization
│   │   ├── clients/      # Clients for external services (e.g., Guacamole, Kubernetes)
│   │   ├── config/       # Configuration loading
│   │   ├── core/         # Core components (e.g., security)
│   │   └── utils/        # Utility functions
│   └── desktop_manager.egg-info/
├── tests/                # Pytest test suite
├── .pre-commit-config.yaml # Pre-commit hook configurations
├── Dockerfile            # Docker configuration for building the API image
├── pyproject.toml        # Project metadata, dependencies, tool configurations
├── uv.lock               # Pinned Python dependencies
├── healthcheck.sh        # Script used for Docker healthcheck
└── ... (other config/cache files)
```

## Database Setup

-   The application requires a **PostgreSQL** database.
-   Database connection details are configured via environment variables (see `Installation` section).
-   **Initialization:**
    -   The Docker Compose setup automatically runs the `.sql` scripts in the `/docker-entrypoint-initdb.d/` directory of the PostgreSQL container on first startup.
    -   `guacamole-init-postgres.sql`: Sets up the necessary tables for Guacamole.
    -   `guacamole-init-users-postgres.sql`: Initializes default Guacamole users/permissions.
    -   Manual initialization might be required if not using the provided Docker Compose setup.

## Prerequisites

Before you begin, ensure you have the following installed:

-   **Python:** Version 3.11 or higher.
-   **uv or pip:** For Python package management (`uv` is recommended).
-   **Docker & Docker Compose:** Required for running the local development environment (API, PostgreSQL, Guacamole, etc.).
-   **psql:** (Optional) Command-line client for PostgreSQL, useful for direct database inspection.
-   **pre-commit:** For managing Git hooks.

## Installation

These steps are primarily for setting up the local environment for development *on this specific API service*. For running the *entire system*, refer to the `docker-compose.yaml` in the project root.

1.  **Clone the repository:** (If you haven't already)
    ```bash
    git clone <your-repository-url>
    cd <repository-root>/desktop-manager-api
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
    The API relies heavily on environment variables for configuration. When running via the root `docker-compose.yaml`, these are set within the compose file itself, often referencing a `.env` file in the project root.


    Key variables for *this API service* include:
    ```dotenv
    # --- Database Settings --- #
    POSTGRES_HOST=postgres
    POSTGRES_PORT=5432
    POSTGRES_DATABASE=your_db_name
    POSTGRES_USER=your_db_user
    POSTGRES_PASSWORD=your_db_password

    # --- Application Settings --- #
    SECRET_KEY=your_strong_random_secret_key # Used for Flask sessions, JWT signing etc.
    ADMIN_OIDC_SUB=your_admin_oidc_subject # OIDC subject claim for the default admin user

    # --- Guacamole Settings --- #
    GUACAMOLE_URL=http://guacamole:8080/guacamole # Internal URL for API to reach Guacamole
    GUACAMOLE_USERNAME=guacadmin # Admin user for API to interact with Guacamole API
    GUACAMOLE_PASSWORD=your_guacadmin_password
    GUACAMOLE_JSON_SECRET_KEY=your_guacamole_json_auth_secret # If using Guacamole JSON auth extension
    EXTERNAL_GUACAMOLE_URL=http://localhost:8080/guacamole # External URL used in frontend redirects

    # --- OIDC Settings (for python-social-auth) --- #
    SOCIAL_AUTH_OIDC_PROVIDER_URL=https://your_oidc_provider.com/oidc
    SOCIAL_AUTH_OIDC_CLIENT_ID=your_api_oidc_client_id
    SOCIAL_AUTH_OIDC_CLIENT_SECRET=your_api_oidc_client_secret
    SOCIAL_AUTH_OIDC_CALLBACK_URL=http://localhost:5000/api/auth/oidc/callback # Backend callback
    SOCIAL_AUTH_OIDC_FRONTEND_REDIRECT_URI=http://localhost:5001/auth/oidc/callback # Frontend callback
    FRONTEND_URL=http://localhost:5001 # URL of the frontend application

    # --- Kubernetes/Rancher Settings (Optional, if features are used) --- #
    RANCHER_API_TOKEN=
    RANCHER_API_URL=
    RANCHER_CLUSTER_ID=
    RANCHER_REPO_NAME=
    NAMESPACE=

    # --- CORS Settings --- #
    CORS_ALLOWED_ORIGINS=http://localhost:5001,http://desktop-frontend:5000 # Comma-separated list

    # --- Development Settings --- #
    FLASK_DEBUG=1 # Set to 1 for development mode
    ```
    *Note:* Refer to `src/config/settings.py` for defaults and the root `docker-compose.yaml` for the definitive development setup.

5.  **Install pre-commit hooks:** (Run from within the `desktop-manager-api` directory)
    ```bash
    pre-commit install
    ```

## Running the API (Local Development)

This API service is **not designed to be run standalone**. It requires at least a **PostgreSQL** database and potentially other services defined in the root `docker-compose.yaml` (like Guacamole, Guacd, Redis for the frontend, etc.).

The recommended way to run the full system for development is using Docker Compose from the **project root directory**:

1.  Navigate to the project root directory (the one containing `docker-compose.yaml`).
2.  Ensure you have a `.env` file in the root directory with all the required environment variables defined.
3.  Start all services:
    ```bash
    docker-compose up -d
    ```
4.  The API service should then be running and accessible *internally* to other Docker containers (e.g., the frontend) at `http://desktop-api:5000`. It is also exposed externally on port `5000` by default in the compose file (`http://localhost:5000`).

Running `flask run` or `gunicorn` directly within the `desktop-manager-api` directory *without* the database and potentially other services will likely result in errors.

## Running with Docker

As mentioned above, Docker (specifically Docker Compose) is the primary way to run the API locally for development, alongside its dependencies.

The `desktop-manager-api/Dockerfile` defines how to build the image for this specific API service. The `docker-compose.yaml` file in the **project root** orchestrates the building and running of this service along with all its dependencies.

Please refer to the `docker-compose.yaml` in the project root for details on:
-   Building the development image (usually includes `FLASK_DEBUG=1` build arg).
-   Service dependencies (PostgreSQL, Guacamole, etc.).
-   Network configuration.
-   Volume mounts for live code reloading during development (`./desktop-manager-api/src:/app/src`).
-   Database initialization via SQL scripts.
-   Environment variable injection.

To build/run only this service (e.g., after changes), you can use compose commands from the root directory:
```bash
# Rebuild the API service image
docker-compose build desktop-api

# Stop and restart only the API service (and potentially dependent services)
docker-compose stop desktop-api
docker-compose up -d desktop-api
```

## Running Tests


**Running Locally (Requires local Python env setup):**
```bash
python -m pytest tests/

# With coverage
python -m pytest tests/ --cov=src
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
    docker-compose run --rm desktop-api pre-commit run --all-files
    ```
-   **Manual Formatting:** A helper script `format_code.sh` is provided which runs `ruff` formatting and checking:
    ```bash
    # Run locally
    ./format_code.sh

    # Or run within the Docker container
    docker-compose run --rm desktop-api /bin/bash -c "./format_code.sh"
    ```
Configuration is in `.pre-commit-config.yaml` and `pyproject.toml` (`[tool.ruff]`).

## Deployment

The primary deployment strategy for this API and the entire Desktop Manager system is using **Kubernetes with Helm**.

While the `desktop-manager-api/Dockerfile` can be used to build a production-ready image (by setting `FLASK_DEBUG=0` during build), the deployment process typically involves:

1.  Packaging the application along with its Kubernetes manifests into a Helm chart.
2.  Configuring environment-specific values (secrets, database credentials, API URLs, resource limits, OIDC details, etc.) via Helm values files.
3.  Ensuring the database schema is initialized/migrated (potentially via Helm hooks or a separate job).
4.  Deploying the chart to a Kubernetes cluster using `helm install` or `helm upgrade`.

Refer to the Helm chart definition (if available in the repository) for specific deployment instructions and configuration options.

Running the API using `docker run` or Docker Compose in production is generally **not recommended** compared to a proper Kubernetes/Helm deployment, especially due to the need for managing the database and other potential stateful dependencies.

## API Endpoints Overview

The API exposes several sets of endpoints, organized by Flask Blueprints:

-   **/api/connections/** (`connection_routes.py`):
    -   Manages user connections, likely related to Guacamole connections (CRUD operations, details, parameters).
-   **/api/desktop-config/** (`desktop_configuration_routes.py`):
    -   Handles configuration settings specific to user desktops or sessions.
-   **/api/users/** (`user_routes.py`):
    -   Manages user information within the Desktop Manager system (listing users, potentially user details).
-   **/api/storage-pvcs/** (`storage_pvc_routes.py`):
    -   Manages Persistent Volume Claims (PVCs) related to user storage, likely interacting with Kubernetes.
-   **/api/auth/oidc/** (`oidc_routes.py`):
    -   Handles the OpenID Connect (OIDC) authentication flow (login initiation, callback processing) using `python-social-auth`.
-   **/api/token/** (`token_routes.py`):
    -   Provides endpoints for obtaining API tokens (e.g., JWTs) after successful authentication, potentially used by the frontend to authenticate subsequent requests.
-   **/api/health** (`main.py`):
    -   A simple health check endpoint to verify API and database connectivity.

*Note: This is a high-level overview. Refer to the route definitions in `src/routes/` for specific endpoints, methods, request/response formats, and required permissions.*

## Authentication/Authorization

-   **Primary Authentication:** OpenID Connect (OIDC) is the main method for user authentication, implemented using `python-social-auth`.
    -   The flow typically starts with the frontend redirecting the user to the OIDC provider (`SOCIAL_AUTH_OIDC_PROVIDER_URL`).
    -   After successful login at the provider, the user is redirected back to the API's callback endpoint (`/api/auth/oidc/callback`, configured by `SOCIAL_AUTH_OIDC_CALLBACK_URL`).
    -   The API backend verifies the OIDC token, retrieves user information, and creates/updates the user in its own database and potentially in Guacamole.
    -   A session or token is likely generated for the user.
-   **Admin User:** A default administrative user is identified based on the OIDC subject claim specified in the `ADMIN_OIDC_SUB` environment variable. This user is automatically granted admin privileges within the application upon first login via OIDC.
-   **API Tokens (JWT):** The `/api/token/` endpoint suggests the API issues tokens (likely JWTs, given the `PyJWT` dependency) after authentication. These tokens are probably used by the frontend to authorize subsequent API requests.
-   **Authorization:** Endpoint access control is likely implemented within the route handlers or decorators, checking user roles (e.g., `is_admin`) or permissions based on the authenticated user session or token.
-   **Guacamole Authentication:** The API manages user authentication within Guacamole, potentially creating users and associating them based on OIDC identity. It uses the `GUACAMOLE_USERNAME` and `GUACAMOLE_PASSWORD` to interact with the Guacamole API. If `GUACAMOLE_JSON_SECRET_KEY` is set, it may also leverage Guacamole's JSON authentication extension.
