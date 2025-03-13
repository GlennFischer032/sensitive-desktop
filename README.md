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

## Testing

The project includes comprehensive test suites for both the API and web application components.

### Test Script

The repository includes a Python script `run_tests.py` that can be used to run tests for both components.

#### Basic Usage

Run all tests for both components:

```bash
./run_tests.py
```

Run tests for just the API component:

```bash
./run_tests.py --component api
```

Run tests for just the web application component:

```bash
./run_tests.py --component app
```

#### Options

The test script supports several options:

- `--component {api,app,all}`: Specify which component to test (default: all)
- `--verbose, -v`: Enable verbose output
- `--failfast, -f`: Stop on first test failure
- `--junit-xml FILENAME`: Generate JUnit XML report with the specified base filename
- `--test-path PATH`: Run a specific test (e.g., tests/unit/test_users.py::test_dashboard_success)
- `--coverage, -c`: Run tests with coverage reporting
- `--debug, -d`: Run tests with debug logging enabled

#### Examples

Run all tests with verbose output:

```bash
./run_tests.py -v
```

Run API tests and stop on first failure:

```bash
./run_tests.py --component api -f
```

Run a specific test in the app component:

```bash
./run_tests.py --component app --test-path tests/unit/test_connections.py::test_list_connections
```

Generate JUnit XML reports:

```bash
./run_tests.py --junit-xml test_report
```

Run tests with coverage reporting:

```bash
./run_tests.py --coverage
```

Run tests with debug logging:

```bash
./run_tests.py --debug
```

### Handling Authentication in Tests

The app component tests require authentication. The test framework automatically mocks JWT token validation to ensure that authentication works correctly during testing. This includes:

1. Setting up proper session data for the test client
2. Mocking JWT token validation with expiration dates
3. Handling both regular user and admin authentication scenarios

If you're experiencing authentication issues in tests, make sure:
- The test client has a proper session setup
- The JWT mock is correctly patched
- Admin-required routes have the admin flag set in the session

### Manual Testing

You can also run the tests directly using pytest:

For the API component:

```bash
cd desktop-manager-api
python -m pytest
```

For the App component:

```bash
cd app
python -m pytest
```

## Code Formatting and Quality

This project uses automated code formatting and quality tools like Black, Ruff, and isort to maintain consistent code quality. Pre-commit hooks are set up to automatically check and format code when committing changes.

For detailed information about code formatting, linting, and pre-commit hooks, see:
- [Code Formatting Documentation](CODE_FORMATTING.md)

To quickly set up pre-commit hooks for the entire project:
```bash
./install_pre_commit.sh
```

To manually format all code in the project:
```bash
./format_all.sh
```
