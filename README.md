# Secure Desktop

A comprehensive remote desktop management system built on Apache Guacamole, providing secure remote desktop access with advanced user and configuration management capabilities.

## Overview

Sensitive Desktop is a complete solution for managing remote desktop connections with a focus on security, scalability, and user experience. The system consists of three main components:

1. **Desktop Manager API**: Backend service that handles business logic, database operations, and communication with external services like Guacamole.

2. **Desktop Frontend**: Web interface that provides an intuitive user experience and securely proxies requests to the backend API.

3. **Deployment Configuration**: Helm charts for deploying the entire solution to Kubernetes.

The system supports OIDC-based authentication, persistent storage for user data, and containerized desktop environments.

## Repository Structure

```
sensitive-desktop/
├── app/                 # Web frontend application
├── desktop-manager-api/ # Backend API service
├── guacamole-helm/      # Helm chart for Kubernetes deployment
│   └── docker/
│       └── desktops/    # Custom desktop configurations
└── docker-compose.yaml  # Development environment configuration
```

Each component has its own detailed README:
- [Desktop Manager API Documentation](desktop-manager-api/README.md)
- [Desktop Frontend Documentation](app/README.md)
- [Helm Chart Documentation](guacamole-helm/README.md)
- [Custom Desktop Configurations](guacamole-helm/docker/desktops/README.md)

## Features

- **Remote Desktop Access**: Secure access to virtual desktops using various protocols (RDP, VNC, SSH) via Apache Guacamole
- **User Management**: User authentication, authorization, and profile management
- **Desktop Configuration**: Customizable desktop environments and persistent user storage
- **Custom Desktop Images**: Create your own custom desktop environments with pre-installed software
- **Security**: OIDC authentication, JWT tokens, secure password management, and CORS protection
- **Scalability**: Kubernetes-based deployment with Helm for easy scaling and management
- **Developer Experience**: Comprehensive test suite, linting tools, and pre-commit hooks

## Quick Start

### Prerequisites

- Docker and Docker Compose (for development)
- Kubernetes and Helm (for production deployment)
- OIDC provider credentials
- PostgreSQL database
- Python 3.11+

### Development Setup

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd sensitive-desktop
   ```

2. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

3. Update the `.env` file with your configuration values (including OIDC credentials)

4. Install pre-commit hooks:
   ```bash
   ./install_pre_commit.sh
   ```

5. Start the development environment:
   ```bash
   docker-compose up -d
   ```

6. Access the application at http://localhost:5001

For more detailed setup instructions, refer to the component-specific README files.

## OIDC Configuration

The system uses OpenID Connect (OIDC) for authentication. To configure OIDC:

### 1. Obtain OIDC Credentials

You'll need the following from your OIDC provider:
- Client ID
- Client Secret
- Provider URL
- Callback URL

#### Using Your Own OIDC Provider:

> **⚠️ WARNING**: The application has only been tested with the e-infra.cz OIDC provider. While it should work with other standard OIDC providers (Keycloak, Auth0, etc.) with minimal adjustments, you may encounter provider-specific issues that require additional configuration.

1. Register a new application with your OIDC provider (e.g., Keycloak, Auth0, Google, etc.)
2. Configure the application with the appropriate redirect URIs:
   - For development: `http://localhost:5001/auth/oidc/callback`
   - For production: `https://your-domain.com/auth/oidc/callback`
3. Obtain the client credentials (Client ID and Client Secret)
4. Note the provider's OIDC endpoint URL

#### Using e-infra.cz OIDC Provider:

The default configuration uses the e-infra.cz OIDC provider. To obtain credentials:

1. Visit [https://spadmin.e-infra.cz/](https://spadmin.e-infra.cz/) and request an **OIDC** service
2. Fill out the administrative data as required
3. For the application-specific settings, use the following configuration:

   **URL of login page:**
   ```
   https://manage-desktops-{desired-release-name}-{rancher-namespace-of-deployer}ns.dyn.cloud.e-infra.cz/auth/login
   ```

   > **Note:** The `manage-desktops` prefix in the hostname is customizable and can be changed or removed by modifying the ingress templates in the Helm chart. See the [Helm Chart Documentation](guacamole-helm/README.md) for details on customizing hostnames.

   **Redirect URIs:**
   ```
   https://manage-desktops-{desired-release-name}-{rancher-namespace-of-deployer}ns.dyn.cloud.e-infra.cz/auth/oidc/callback
   ```

   If you plan to run in local development mode, also add:
   ```
   http://localhost:5001/auth/oidc/callback
   ```

   **Flow the service will use:**
   `authorization code`

   **Token endpoint authentication method:**
   `client_secret_basic`

   **Proof Key for Code Exchange (PKCE) Code Challenge Method:**
   `SHA256 code challenge`

   **Service will call introspection endpoint:**
   `true`

   **Scopes the service will use:**
   - `openid`
   - `profile`
   - `email`
   - `organization`
   - `offline_access`

   **Issue refresh tokens for this client:**
   `true`

   **Check the box if you would like the AAI to check users' memberships in required groups:**
   `false`

   **Allow registration to get access to the service:**
   `false`

   **Allow proxy registration form:**
   `false`

   **Registration URL:**
   Leave empty

4. After your request is approved, you will receive the Client ID and Client Secret for your application

### 2. Configure the Application

Add your OIDC credentials to the `.env` file for development:

```dotenv
OIDC_PROVIDER_URL=https://your-provider-url/oidc
OIDC_CLIENT_ID=your_client_id
OIDC_CLIENT_SECRET=your_client_secret
OIDC_CALLBACK_URL=http://localhost:5001/auth/oidc/callback
```

For production deployment, update the values in your Helm values file:

```yaml
common:
  oidc:
    clientId: "your_client_id"
    clientSecret: "your_client_secret"
    providerUrl: "https://your-provider-url/oidc"
    redirectUri: "https://your-domain.com/auth/oidc/callback"
  credentials:
    desktopAdmin:
      oidcSub: "your-admin-oidc-sub"  # Subject identifier for admin user
```

### 3. Retrieving OIDC Subject Identifiers

The system requires an OIDC subject identifier (sub) for the default admin user. This is configured in the `common.credentials.desktopAdmin.oidcSub` field in your Helm values file.

#### For e-infra.cz users:

1. Log in to [https://profile.e-infra.cz/profile](https://profile.e-infra.cz/profile)
2. Your OIDC subject identifier will be displayed on your profile page
3. Copy this value and use it for the `oidcSub` field in your configuration

#### For other OIDC providers:

You can typically retrieve your subject identifier by:
1. Using an OpenID Connect debugger tool
2. Creating a simple application that displays the decoded ID token
3. Checking your identity provider's user profile page
4. Using developer tools to inspect the ID token when logging in

The subject identifier is a unique string that identifies the user within the OIDC system.

## Deployment

For development, use Docker Compose:
```bash
docker-compose up -d
```

For production deployment, use Helm:
```bash
cd guacamole-helm
# Generate secure credentials if needed
python generate-secrets.py values.yaml values.local.yaml
# Deploy the application
helm install sensitive-desktop . -f values.local.yaml
```

> **Note:** By default, the Helm chart will deploy the frontend with a hostname like `manage-desktops-{release-name}-{namespace}ns.dyn.cloud.e-infra.cz` and Guacamole with a hostname based on a similar pattern. These hostname patterns can be customized by modifying the ingress templates. See the [Helm Chart Documentation](guacamole-helm/README.md) for details.

For detailed deployment instructions, refer to the [Helm Chart Documentation](guacamole-helm/README.md).

## Development

### Code Quality

This project uses pre-commit hooks to enforce code quality standards:

```bash
# Install pre-commit hooks
./install_pre_commit.sh

# Run pre-commit manually
pre-commit run --all-files
```

### Running Tests

Each component has its own test suite. Refer to the component-specific README files for instructions on running tests.
