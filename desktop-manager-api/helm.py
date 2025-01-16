import subprocess
import yaml
import os
import re
from config import Config

def helm_install(connection_name, values, helm_chart_path):
    # Write the modified values to a temporary file
    try:
        with open(Config.TEMP_VALUES_FILE_PATH, 'w') as f:
            yaml.dump(values, f)
    except Exception as e:
        raise Exception(f"Failed to write temporary values.yaml: {str(e)}")
    print(values)
    # Helm install command using the temporary values file
    command = [
        'helm', 'install', connection_name, helm_chart_path,
        '--namespace', Config.NAMESPACE,
        f'--values={Config.TEMP_VALUES_FILE_PATH}'
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
        os.remove(Config.TEMP_VALUES_FILE_PATH)

        return ip_address
    except subprocess.CalledProcessError as e:
        # Clean up the temporary values file if it exists
        if os.path.exists(Config.TEMP_VALUES_FILE_PATH):
            os.remove(Config.TEMP_VALUES_FILE_PATH)
        raise Exception(f"Failed to install Helm chart: {e.stderr}")

def helm_uninstall(connection_name):
    # Helm uninstall command
    command = [
        'helm', 'uninstall', connection_name,
        '--namespace', Config.NAMESPACE
    ]

    try:
        subprocess.run(
            command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
    except subprocess.CalledProcessError as e:
        # Log the error but proceed
        print(f"Helm uninstall error for '{connection_name}': {e.stderr}")
