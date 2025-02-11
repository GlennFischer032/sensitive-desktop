# Sensitive Desktop Project

A comprehensive solution for managing and accessing remote desktops in a secure, containerized environment. This project combines Apache Guacamole's remote desktop gateway capabilities with a custom Desktop Manager interface for automated desktop provisioning and management.

## Quick Start with Docker Compose

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd sensitive-desktop
   ```

2. Create a `.env` file with the following required variables:
   ```env
   # Database Configuration
   MYSQL_ROOT_PASSWORD=your_root_password
   MYSQL_DATABASE=guacamole_db
   MYSQL_USER=guacamole_user
   MYSQL_PASSWORD=your_password

   # Guacamole Admin Credentials
   GUACAMOLE_USERNAME=guacadmin
   GUACAMOLE_PASSWORD=guacadmin
   GUACAMOLE_API_URL=http://guacamole:8080/guacamole/api
   GUACAMOLE_URL=http://guacamole:8080/guacamole

   # Desktop Manager API Configuration
   SECRET_KEY=your_secret_key
   ADMIN_USERNAME=admin
   ADMIN_PASSWORD=your_admin_password

   # Rancher Configuration
   RANCHER_API_TOKEN=your_rancher_token
   RANCHER_API_URL=https://rancher.cloud.e-infra.cz
   RANCHER_CLUSTER_ID=your_cluster_id
   RANCHER_REPO_NAME=your_repo
   NAMESPACE=your_namespace
   ```

3. Start the services:
   ```bash
   docker-compose up -d
   ```

4. Access the applications:
   - Desktop Manager Frontend: http://localhost:5001
   - Desktop Manager API: http://localhost:5000
   - Guacamole: http://localhost:8080/guacamole

## Services Overview

The project consists of several interconnected services:

- **Desktop Manager Frontend** (port 5001)
  - Web interface for managing remote desktops
  - User authentication and desktop management
  - Connection to remote desktops via Guacamole

- **Desktop Manager API** (port 5000)
  - Backend service for desktop provisioning
  - User and connection management
  - Integration with Rancher

- **Apache Guacamole** (port 8080)
  - Remote desktop gateway
  - Supports RDP, VNC, and SSH protocols
  - Web-based remote desktop viewer

- **MySQL Database** (port 3306)
  - Stores user data and connections
  - Manages Guacamole configurations
  - Handles desktop manager state

## Basic Usage

1. **First Login**
   - Access the Desktop Manager at http://localhost:5001
   - Log in with the admin credentials set in `.env`
   - Create additional users as needed

2. **Creating a Desktop**
   - Click "Connections" in the navigation menu
   - Create a new connection
   - Wait for provisioning to complete

3. **Accessing Desktops**
   - Select "Connect" on a connection to launch the remote session
   - Use the same credentials as for the Desktop Manager Frontend
   - Use the Guacamole interface to interact with the desktop

## Using Guacamole Interface

When accessing a remote desktop through Guacamole, you have access to several features:

1. **Basic Navigation**
   - Use your mouse and keyboard as normal
   - Press Ctrl+Alt+Shift to access the Guacamole menu

2. **Guacamole Menu Options**
   - Screen: Zoom, display settings, and fullscreen mode
   - Clipboard: Disabled for security reasons
   - Input Methods: Change keyboard layout
   - Settings: Adjust mouse, display, and performance settings

4. **Common Keyboard Shortcuts**
   - Ctrl+Alt+Shift: Show/hide Guacamole menu
   - Ctrl+Alt+Enter: Toggle fullscreen
   - Ctrl+Alt+PrtScn: Screenshot

For more detailed information about using Guacamole, refer to:
- [Guacamole User Guide](https://guacamole.apache.org/doc/gug/)
- [Using the Guacamole Interface](https://guacamole.apache.org/doc/gug/using-guacamole.html)
- [Keyboard Shortcuts](https://guacamole.apache.org/doc/gug/using-guacamole.html#keyboard-shortcuts)

## Project Structure

```
sensitive-desktop/
├── app/                      # Desktop Manager Frontend
├── desktop-manager-api/      # Desktop Manager API Service
├── guacamole-helm/          # Kubernetes Helm Chart
├── docker-compose.yaml      # Docker Compose configuration
└── README.md               # This file
```

For detailed documentation of individual components, please refer to their respective README files:
- [Desktop Manager Frontend](app/README.md)
- [Desktop Manager API](desktop-manager-api/README.md)
- [Guacamole Helm Chart](guacamole-helm/README.md)