# Sensitive Desktop Project

A comprehensive solution for managing and accessing remote desktops in a secure, containerized environment. This project combines Apache Guacamole's remote desktop gateway capabilities with a custom Desktop Manager interface for automated desktop provisioning and management.

## Project Overview

The Sensitive Desktop project consists of several key components:

1. **Desktop Manager Frontend**
   - Web-based interface for managing remote desktops
   - Built with Flask and modern web technologies
   - Provides intuitive desktop creation and management

2. **Desktop Manager API**
   - RESTful API service for desktop management
   - Integrates with Rancher for container orchestration
   - Handles desktop provisioning and configuration

3. **Apache Guacamole**
   - Remote desktop gateway supporting multiple protocols (RDP, VNC, SSH)
   - Customized for secure, non-root execution
   - Integrated with MySQL for session and connection management

4. **Deployment Options**
   - Docker Compose for development and testing
   - Helm Chart for production Kubernetes deployment

## Project Structure

```
sensitive-desktop/
├── app/                      # Desktop Manager Frontend
├── desktop-manager-api/      # Desktop Manager API Service
├── guacamole-helm/          # Kubernetes Helm Chart
├── docker-compose.yaml      # Docker Compose configuration
├── .env.example            # Example environment variables
└── README.md               # This file
```

## Quick Start

### Development Environment (Docker Compose)

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd sensitive-desktop
   ```

2. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

3. Update the `.env` file with your configuration:
   - Set database credentials
   - Configure Rancher API token
   - Adjust other settings as needed

4. Start the services:
   ```bash
   docker-compose up -d
   ```

5. Access the applications:
   - Desktop Manager: http://localhost:5000
   - Guacamole: http://localhost:8080/guacamole

### Production Deployment (Kubernetes)

1. Navigate to the Helm chart directory:
   ```bash
   cd guacamole-helm
   ```

2. Review and customize `values.yaml`:
   - Set image repositories and tags
   - Configure storage settings
   - Set security parameters
   - Update ingress hostnames

3. Install the Helm chart:
   ```bash
   helm install sensitive-desktop . \
     --namespace your-namespace \
     --set desktopApi.rancherToken=your-rancher-token
   ```

4. Access the applications:
   - Desktop Manager: https://manage-desktops-[RELEASE]-[NAMESPACE].dyn.cloud.e-infra.cz
   - Guacamole: https://[RELEASE]-[NAMESPACE].dyn.cloud.e-infra.cz/guacamole

## Configuration

### Environment Variables

Key environment variables for the project:

```env
# Desktop Manager API
SECRET_KEY=your_secret_key
RANCHER_API_TOKEN=your_rancher_token
RANCHER_API_URL=https://rancher.cloud.e-infra.cz
RANCHER_CLUSTER_ID=your_cluster_id
NAMESPACE=your_namespace

# Database
MYSQL_ROOT_PASSWORD=rootpass
MYSQL_DATABASE=guacamole_db
MYSQL_USER=guacamole_user
MYSQL_PASSWORD=guacpass

# Guacamole
GUACAMOLE_USER=guacadmin
GUACAMOLE_PASSWORD=guacadmin
```

### Helm Chart Values

Key configuration options in `values.yaml`:

- Container images and tags
- Resource limits and requests
- Security contexts
- Ingress configuration
- Storage settings
- Health check parameters

## Development

### Prerequisites

- Docker and Docker Compose
- Kubernetes cluster (for production)
- Helm 3.x
- Python 3.8+

### Building Images

```bash
# Build Desktop Manager API
docker build -t desktop-manager-api ./desktop-manager-api

# Build Desktop Manager Frontend
docker build -t desktop-manager-frontend ./app
```
