import subprocess
import yaml
import os
import re
from desktop_manager.config.settings import get_settings

def helm_install(connection_name, values, helm_chart_path):
    settings = get_settings()
    # Write the modified values to a temporary file
    try:
        with open(settings.TEMP_VALUES_FILE_PATH, 'w') as f:
            yaml.dump(values, f)
    except Exception as e:
        raise Exception(f"Failed to write temporary values.yaml: {str(e)}")
    print(values)
    # Helm install command using the temporary values file
    command = [
        'helm', 'install', connection_name, helm_chart_path,
        '--namespace', settings.NAMESPACE,
        f'--values={settings.TEMP_VALUES_FILE_PATH}'
    ]
    print(command)
    try:
        result = subprocess.run(
            command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        output = result.stdout
        print(output)

        # Extract IP address from Helm output
        match = re.search(r'Navigate VNC viewer to:\s*(\S+)', output)
        if match:
            ip_address = match.group(1)
        else:
            ip_address = None

        # Clean up the temporary values file
        os.remove(settings.TEMP_VALUES_FILE_PATH)

        return ip_address
    except subprocess.CalledProcessError as e:
        # Clean up the temporary values file if it exists
        if os.path.exists(settings.TEMP_VALUES_FILE_PATH):
            os.remove(settings.TEMP_VALUES_FILE_PATH)
        raise Exception(f"Failed to install Helm chart: {e.stderr}")

def helm_uninstall(connection_name):
    settings = get_settings()
    # Helm uninstall command
    command = [
        'helm', 'uninstall', connection_name,
        '--namespace', settings.NAMESPACE
    ]
    try:
        result = subprocess.run(
            command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        raise Exception(f"Failed to uninstall Helm chart: {e.stderr}")
