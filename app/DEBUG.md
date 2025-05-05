# Debugging the Desktop Frontend Application

This guide explains how to debug the Desktop Frontend application running in Docker Compose using the Cursor/VS Code debugger.

## Setup

The debugging configuration has been set up to allow you to attach a debugger to the Flask application running in the `desktop-frontend` container.

### Components

1. **launch.json**: Contains VS Code/Cursor debugger configuration
2. **docker-compose.yaml**: Modified to expose the debug port and run the application with debugpy
3. **debugpy**: Python package that enables remote debugging

## How to Debug

### Step 1: Start the Application with Docker Compose

```bash
# Start up the application
docker-compose up
```


The application will start and wait for the debugger to attach before proceeding (due to the `--wait-for-client` flag).

### Step 2: Attach the Debugger

1. In Cursor/VS Code, go to the "Run and Debug" panel (Ctrl+Shift+D or Cmd+Shift+D on Mac)
2. Select the "Python: Docker Attach (desktop-frontend)" configuration from the dropdown
3. Click the play button or press F5 to attach the debugger

### Step 3: Debug Your Application

Once the debugger is attached:

1. Set breakpoints in your code
2. Use the debug console to inspect variables
3. Step through code execution

## Troubleshooting

### Cannot Connect to Debug Port

- Make sure the application is running in Docker Compose
- Verify that port 5678 is exposed and mapped correctly in the docker-compose.yaml file
- Check Docker logs for any errors:
  ```bash
  docker-compose logs desktop-frontend
  ```

### Breakpoints Not Being Hit

- Confirm that the path mappings in launch.json match your project structure
- Verify that the code you're debugging matches the code in the container

## Advanced Configuration

### Path Mappings

The `pathMappings` in launch.json map your local file paths to paths inside the Docker container:

```json
"pathMappings": [
    {
        "localRoot": "${workspaceFolder}/app",
        "remoteRoot": "/app"
    }
]
```

Adjust these if your local directory structure differs.

### Debug Only Your Code

The `justMyCode` setting is set to `true` to focus debugging on your application code. Set to `false` if you want to debug library code too.
