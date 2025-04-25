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

2. Update `values.local.yaml` with your sensitive data in the `common` section:
   ```yaml
   common:
     database:
       user: "your-db-user"
       password: "your-db-password"
     credentials:
       secretKey: "your-secret-key"
       guacamoleAdmin:
         username: "your-guac-admin"
         password: "your-guac-password"
       desktopAdmin:
         username: "your-desktop-admin"
         password: "your-desktop-password"
     rancher:
       apiUrl: "your-rancher-url"
       clusterId: "your-cluster-id"
       repoName: "your-repo-name"
       token: "your-rancher-token"
   ```

3. Add `values.local.yaml` to your `.gitignore`:
   ```bash
   echo "values.local.yaml" >> .gitignore
   ```

## Installation


```bash
helm install guacamole ./guacamole-helm \
  --namespace your-namespace \
  -f values.local.yaml
```

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
    mysql: 3306      # MySQL database port

  # Database configuration
  database:
    host: mysql-guacamole
    port: "3306"
    user: ""         # Set the database user
    password: ""     # Set the database password
    guacamoleDb: guacamole_db
    desktopDb: desktop_manager

  # Credentials and secrets
  credentials:
    secretKey: ""    # Set a secure secret key
    guacamoleAdmin:
      username: ""   # Set Guacamole admin username
      password: ""   # Set Guacamole admin password
    desktopAdmin:
      username: ""   # Set Desktop Manager admin username
      password: ""   # Set Desktop Manager admin password

  # Rancher configuration
  rancher:
    apiUrl: ""       # Set Rancher API URL
    clusterId: ""    # Set Rancher cluster ID
    repoName: ""     # Set repository name
    token: ""        # Set Rancher API token
```

### Component-Specific Configuration

#### Desktop Manager API
```yaml
desktopApi:
  replicaCount: 1
  image: "glennfischer032/desktop-manager-api:latest"
  containerPort: 5000
  healthcheck:
    enabled: true
    path: /api/health
    initialDelaySeconds: 30
    periodSeconds: 10
    timeoutSeconds: 5
    failureThreshold: 3
```

#### Desktop Manager Frontend
```yaml
desktopFrontend:
  replicaCount: 1
  image: "glennfischer032/desktop-manager-frontend:latest"
  containerPort: 5000
  healthcheck:
    enabled: true
    path: /
    initialDelaySeconds: 10
    periodSeconds: 10
    timeoutSeconds: 5
    failureThreshold: 3
```

#### MySQL
```yaml
mysql:
  image: "mysql:8.0"
  initdbImage: "glennfischer032/guacamole-init-db:latest"
  persistence:
    enabled: true
    storageClass: "nfs-csi"
    accessMode: ReadWriteOnce
    size: 1Gi
  args:
    - "--default-authentication-plugin=mysql_native_password"
    - "--bind-address=0.0.0.0"
  healthcheck:
    enabled: true
```

#### Guacamole and guacd
```yaml
guacd:
  image: "guacamole/guacd"
  logLevel: "info"

guacamole:
  image: "glennfischer032/guac-no-root:latest"
  containerPort: 8080
```

## Security

The chart implements several security best practices:
- All components run as non-root users
- Security contexts are properly configured at both pod and container level
- Container capabilities are dropped
- Sensitive data is managed through the `common.credentials` section
- All services use health checks for reliability

## Maintenance

### Docker Images
Custom Docker images are maintained in the `docker/` directory:
- `guac-no-root`: Guacamole image modified to run as non-root user
- `init-db`: Database initialization image

### Database Initialization
SQL scripts in `sql/` directory:
1. `01-guacamole-init.sql`: Core Guacamole schema

## Secure Credential Management

This Helm chart includes automatic secure credential generation for production deployments. The following credentials are auto-generated during deployment if not explicitly provided:

- **Encryption Key**: A valid Fernet key for encrypting sensitive data
- **Guacamole JSON Secret Key**: Used for Guacamole JSON authentication
- **Database Password**: For PostgreSQL access

### How It Works

1. During pre-install or pre-upgrade, a Kubernetes job called `key-generator` runs
2. This job creates cryptographically secure random keys appropriate for each service
3. The generated keys are stored in a Kubernetes Secret
4. Application pods reference these secrets via environment variables

### Using Your Own Credentials

If you prefer to provide your own credentials, you can set them in your `values.yaml` file:

```yaml
common:
  credentials:
    encryptionKey: "your-fernet-key"  # Must be a valid base64-encoded 32-byte key
    guacamoleJsonSecretKey: "your-guacamole-key"  # Used for JSON authentication
  database:
    password: "your-database-password"  # PostgreSQL password
```

### Generating a Valid Fernet Key

If you need to generate a valid Fernet key outside of the deployment process:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
