# Guacamole and Desktop Manager Helm Chart

This Helm chart deploys Apache Guacamole along with a Desktop Manager solution for managing remote desktop connections.

## Components

### Core Components
- **Apache Guacamole**: Remote desktop gateway
- **guacd**: Guacamole proxy daemon
- **PostgreSQL**: Database for both Guacamole and Desktop Manager
- **Desktop Manager API**: Backend service for managing desktop connections
- **Desktop Manager Frontend**: Web interface for users
- **Redis**: Used for session management

### Directory Structure
```
guacamole-helm/
├── Chart.yaml           # Chart metadata
├── values.yaml          # Default configuration values (template)
├── values.local.yaml    # Local values file with sensitive data (gitignored)
├── README.md            # This file
├── templates/           # Kubernetes manifests
│   ├── api/             # Desktop Manager API related templates
│   ├── frontend/        # Desktop Manager Frontend templates
│   ├── guacamole/       # Guacamole related templates
│   ├── guacd/           # Guacd related templates
│   ├── postgres/        # Database related templates
│   ├── redis/           # Redis related templates
│   └── _helpers.tpl     # Helper templates
└── docker/              # Custom Docker images
    ├── guac-no-root/    # Non-root Guacamole image
    └── desktops/        # Custom desktop image definitions
```

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- PV provisioner support in the underlying infrastructure
- Ingress controller
- Rancher API token for desktop management
- OIDC provider for authentication

## Configuration

### Managing Sensitive Data

This chart uses two values files to manage configuration:

1. `values.yaml`: Template file committed to git with placeholder values
2. `values.local.yaml`: Local file containing sensitive data (not committed to git)

To set up your local environment:

1. Copy the template:
   ```bash
   cp values.yaml values.local.yaml
   ```

2. Update `values.local.yaml` with your sensitive data in the `common` section:
   ```yaml
   common:
     database:
       user: "guacamole_user"
       password: "your-db-password"
       database: "desktop_manager"
     credentials:
       encryptionKey: "your-fernet-key"
       guacamoleJsonSecretKey: "your-guacamole-json-key"
       desktopAdmin:
         oidcSub: "your-oidc-subject-id"
       desktopApiSecretKey: "your-api-secret-key"
       desktopFrontendSecretKey: "your-frontend-secret-key"
     rancher:
       apiUrl: "your-rancher-url"
       clusterId: "your-cluster-id"
       repoName: "your-repo-name"
       token: "your-rancher-token"
       namespace: "your-namespace"
     oidc:
       clientId: "your-oidc-client-id"
       clientSecret: "your-oidc-client-secret"
       providerUrl: "your-oidc-provider-url"
       redirectUri: "your-oidc-redirect-uri"
   ```

## Installation

```bash
helm install guacamole ./guacamole-helm \
  --namespace your-namespace \
  -f values.local.yaml
```

## Customizing Ingress Hostnames

By default, the Helm chart configures ingress resources with the following hostname patterns:

1. **Desktop Frontend Hostname:**
   ```
   manage-desktops-{release-name}-{namespace}ns.dyn.cloud.e-infra.cz
   ```

2. **Guacamole Hostname:**
   ```
   guacamole-{release-name}-{namespace}ns.dyn.cloud.e-infra.cz
   ```

These hostnames are generated by the `desktop-frontend.hostname` and `guacamole.hostname` template functions defined in `_helpers.tpl`.

### Customizing Hostname Prefixes

You can customize or remove the hostname prefixes by modifying the following files:

1. **For Desktop Frontend:** Edit `templates/frontend/desktop-ingress.yaml`
   - Change or remove the `manage-desktops-` prefix in the hostname template
   - Update the TLS secret name accordingly

2. **For Guacamole:** Edit `templates/guacamole/guacamole-ingress.yaml`
   - Change or remove any prefix in the hostname template
   - Update the TLS secret name accordingly

### Example Customization

To use custom hostnames, modify the `_helpers.tpl` file to define custom template functions:

```yaml
{{- define "desktop-frontend.hostname" -}}
{{- printf "custom-prefix-%s-%sns.dyn.cloud.e-infra.cz" .Release.Name .Release.Namespace -}}
{{- end -}}

{{- define "guacamole.hostname" -}}
{{- printf "guac-%s-%sns.dyn.cloud.e-infra.cz" .Release.Name .Release.Namespace -}}
{{- end -}}
```

> **Important:** When customizing hostnames, make sure to update the OIDC configuration in your external identity provider to use the new hostnames for the login URL and redirect URIs.

## Configuration Reference

### Common Configuration

The chart uses a centralized `common` section in the values file for shared configurations:

```yaml
common:
  # Security contexts applied at the Pod level
  podSecurityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
    fsGroupChangePolicy: OnRootMismatch
    fsGroup: 1000

  # Common container security settings
  containerSecurityContext:
    allowPrivilegeEscalation: false
    capabilities:
      drop:
        - ALL

  # Common service ports
  ports:
    api: 80          # Desktop Manager API port
    frontend: 80     # Desktop Manager Frontend port
    guacamole: 80    # Guacamole web interface port
    guacd: 4822      # Guacamole proxy daemon port
    postgres: 5432   # PostgreSQL database port
    redis: 6379      # Redis port

  # Database configuration
  database:
    host: postgres-guacamole
    port: "5432"
    user: "guacamole_user"  # Set the database user
    password: ""            # Set the database password (will be auto-generated if empty)
    database: desktop_manager

  # Credentials and secrets
  credentials:
    secretKey: ""           # Set a secure secret key for the application
    encryptionKey: ""       # Set a valid Fernet key for encryption
    guacamoleJsonSecretKey: "" # Set JSON auth secret key for Guacamole
    desktopAdmin:
      oidcSub: ""           # Set the Desktop Manager admin OIDC subject
    desktopApiSecretKey: "" # Secret key for desktop API
    desktopFrontendSecretKey: "" # Secret key for desktop frontend if using debug mode

  # OIDC Configuration
  oidc:
    clientId: ""           # Set your OIDC client ID
    clientSecret: ""       # Set your OIDC client secret
    providerUrl: ""        # Set your OIDC provider URL
    redirectUri: ""        # Set your OIDC redirect URI

  # Rancher configuration
  rancher:
    apiUrl: ""            # Set your Rancher API URL
    clusterId: ""         # Set your Rancher cluster ID
    repoName: ""          # Set your repository name
    token: ""             # Set your Rancher API token
    namespace: ""         # Set your namespace
```

### Component-Specific Configuration

#### Desktop Manager API
```yaml
desktopApi:
  replicaCount: 1
  image: "gitlab.fi.muni.cz:5050/xfischer/sensitive-desktop/desktop-manager-api:latest"
  containerPort: 5000
  healthcheck:
    enabled: true
    path: /api/health
    initialDelaySeconds: 10
    periodSeconds: 10
    timeoutSeconds: 5
    failureThreshold: 3
```

#### Desktop Manager Frontend
```yaml
desktopFrontend:
  replicaCount: 1
  image: "gitlab.fi.muni.cz:5050/xfischer/sensitive-desktop/desktop-manager-frontend:latest"
  containerPort: 5000
  healthcheck:
    enabled: true
    path: /health
    initialDelaySeconds: 5
    periodSeconds: 10
    timeoutSeconds: 5
    failureThreshold: 3
```

#### PostgreSQL
```yaml
postgres:
  image: "postgres:16-alpine"
  persistence:
    enabled: true
    storageClass: "nfs-csi"
    accessMode: ReadWriteOnce
    size: 1Gi
  healthcheck:
    enabled: true
    command: ["pg_isready", "-U", "$(POSTGRES_USER)"]
    initialDelaySeconds: 10
    periodSeconds: 10
    timeoutSeconds: 5
    failureThreshold: 5
```

#### Redis
```yaml
redis:
  image: "redis:7-alpine"
  containerPort: 6379
  healthcheck:
    enabled: true
    command: ["redis-cli", "ping"]
    initialDelaySeconds: 5
    periodSeconds: 5
    timeoutSeconds: 3
    failureThreshold: 3
```

#### Guacamole and guacd
```yaml
guacd:
  image: "guacamole/guacd"
  logLevel: "info"

guacamole:
  image: "gitlab.fi.muni.cz:5050/xfischer/sensitive-desktop/guac-no-root:latest"
  containerPort: 8080
  extensionPriority: "json"
```

## Security

The chart implements several security best practices:
- All components run as non-root users
- Security contexts are properly configured at both pod and container level
- Container capabilities are dropped
- Sensitive data is managed through the `common.credentials` section
- OIDC-based authentication for secure user access
- All services use health checks for reliability

## Authentication

The system uses OpenID Connect (OIDC) for authentication. Configure the following OIDC parameters:

```yaml
common:
  oidc:
    clientId: ""           # Your OIDC client ID
    clientSecret: ""       # Your OIDC client secret
    providerUrl: ""        # Your OIDC provider URL (e.g., https://your-oidc-provider/oidc)
    redirectUri: ""        # Callback URL for authentication
```

## Secure Credential Management

This Helm chart requires several secure credentials for production deployments. These credentials are NOT auto-generated during deployment and must be either explicitly provided or generated using the included utility script before deployment:

- **Encryption Key**: A valid Fernet key for encrypting sensitive data
- **Guacamole JSON Secret Key**: Used for Guacamole JSON authentication
- **Database Password**: For PostgreSQL access
- **Application Secret Keys**: For the API and frontend services

### How It Works

The credentials must be provided in your values file and are stored in Kubernetes Secrets during deployment. Applications reference these secrets via environment variables.

### Using Your Own Credentials

You can manually set credentials in your `values.local.yaml` file:

```yaml
common:
  credentials:
    encryptionKey: "your-fernet-key"  # Must be a valid base64-encoded 32-byte key
    guacamoleJsonSecretKey: "your-guacamole-key"  # Used for JSON authentication
    desktopApiSecretKey: "your-api-secret-key"  # For the API service
    desktopFrontendSecretKey: "your-frontend-secret-key"  # For the frontend service
  database:
    password: "your-database-password"  # PostgreSQL password
```

### Generating a Valid Fernet Key

If you need to generate a valid Fernet key outside of the deployment process:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## Credentials Generator Utility

This project includes a utility script `generate-secrets.py` that automatically generates and updates missing credentials in your values file. The script can generate:

- Fernet encryption keys
- Guacamole JSON secret keys
- Database passwords
- Application secret keys
- Frontend secret keys

### Using the Generator

```bash
# Basic usage - automatically detects values.local.yaml or falls back to values.yaml
python generate-secrets.py

# Specify input and output files
python generate-secrets.py values.yaml values.local.yaml
```

The script will only generate credentials that are missing - existing values will be preserved. Once the script completes, you can deploy using the updated values file:

```bash
helm install guacamole . -n your-namespace -f values.local.yaml
```
