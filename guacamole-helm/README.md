# Guacamole and Desktop Manager Helm Chart

This Helm chart deploys Apache Guacamole along with a Desktop Manager solution for managing remote desktop connections.

## Components

### Core Components
- **Apache Guacamole**: Remote desktop gateway
- **guacd**: Guacamole proxy daemon
- **MySQL**: Database for both Guacamole and Desktop Manager
- **Desktop Manager API**: Backend service for managing desktop connections
- **Desktop Manager Frontend**: Web interface for users

### Directory Structure
```
guacamole-helm/
├── Chart.yaml           # Chart metadata
├── values.yaml         # Default configuration values (template)
├── values.local.yaml   # Local values file with sensitive data (gitignored)
├── README.md          # This file
├── templates/         # Kubernetes manifests
│   ├── desktop/      # Desktop Manager related templates
│   ├── guacamole/    # Guacamole related templates
│   ├── mysql/        # Database related templates
│   └── _helpers/     # Helper templates and notes
├── sql/              # SQL initialization scripts
└── docker/           # Custom Docker images
    ├── guac-no-root/ # Non-root Guacamole image
    └── init-db/      # Database initialization image
```

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- PV provisioner support in the underlying infrastructure
- Ingress controller
- Rancher API token for desktop management

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

2. Update `values.local.yaml` with your sensitive data:
   - Rancher API token
   - Database passwords
   - Admin credentials
   - Secret keys
   - API URLs and endpoints

3. Add `values.local.yaml` to your `.gitignore`:
   ```bash
   echo "values.local.yaml" >> .gitignore
   ```

## Installation

### Secure Installation (Recommended for Production)

1. Create a Kubernetes secret with your Rancher API token:
```bash
kubectl create secret generic rancher-token-secret \
  --from-literal=token=your-rancher-token \
  --namespace your-namespace
```

2. Install the chart using your local values:
```bash
helm install guacamole ./guacamole-helm \
  --namespace your-namespace \
  -f values.local.yaml \
  --set desktopApi.existingRancherToken=$(kubectl get secret rancher-token-secret -n your-namespace -o jsonpath='{.data.token}')
```

### Quick Installation (Development Only)

```bash
helm install guacamole ./guacamole-helm \
  --namespace your-namespace \
  -f values.local.yaml
```

## Configuration

### Important Parameters

#### Desktop Manager API
- `desktopApi.image`: API service image
- `desktopApi.existingRancherToken`: Base64 encoded Rancher API token from an existing secret (recommended)
- `desktopApi.rancherToken`: Direct Rancher API token (not recommended for production)
- `desktopApi.env.*`: Environment variables for API configuration

### Rancher Token Configuration

The Rancher API token is managed through a Kubernetes secret created by the chart. You can configure it in two ways:

1. **Using an Existing Token (Recommended for Production)**
   ```bash
   # First, create a Kubernetes secret with your token
   kubectl create secret generic rancher-token-secret \
     --from-literal=token=your-rancher-token \
     --namespace your-namespace

   # Then install the chart using the existing token
   helm install guacamole ./guacamole-helm \
     --namespace your-namespace \
     -f values.local.yaml \
     --set desktopApi.existingRancherToken=$(kubectl get secret rancher-token-secret -n your-namespace -o jsonpath='{.data.token}')
   ```

2. **Direct Token (Development Only)**
   ```bash
   # Set the token directly in values.local.yaml
   desktopApi:
     rancherToken: "your-rancher-token"
   ```
   Or via command line:
   ```bash
   helm install guacamole ./guacamole-helm \
     --namespace your-namespace \
     -f values.local.yaml \
     --set desktopApi.rancherToken=your-rancher-token
   ```

The token is managed by `templates/desktop/secret-desktop-api.yaml`, which creates a secret named `desktop-api-<release-name>`. This secret is then mounted as the environment variable `RANCHER_API_TOKEN` in the desktop-api container.

**Note**: Never commit the actual token to version control. Always use `values.local.yaml` or command-line parameters to set the token.

#### Desktop Manager Frontend
- `desktopFrontend.image`: Frontend service image
- `desktopFrontend.env.*`: Environment variables for frontend configuration

#### MySQL
- `mysql.rootPassword`: Root password (set in values.local.yaml)
- `mysql.userPassword`: User password (set in values.local.yaml)
- `mysql.persistence.*`: Persistence configuration

#### Guacamole
- `guacamole.adminUser`: Admin username (set in values.local.yaml)
- `guacamole.adminPassword`: Admin password (set in values.local.yaml)

See `values.yaml` for complete configuration options and `values.local.yaml` for your local sensitive values.

## Security

- All components run as non-root users
- Security contexts are properly configured
- Capabilities are dropped where possible
- Secrets are properly managed

## Maintenance

### Docker Images
Custom Docker images are maintained in the `docker/` directory:
- `guac-no-root`: Guacamole image modified to run as non-root user
- `init-db`: Database initialization image

### Database Initialization
SQL scripts in `sql/` directory:
1. `01-guacamole-init.sql`: Core Guacamole schema
2. `02-guacamole-init-users.sql`: User initialization
3. `03-init.sql`: Additional initialization
4. `04-desktop-manager-schema.sql`: Desktop Manager schema

