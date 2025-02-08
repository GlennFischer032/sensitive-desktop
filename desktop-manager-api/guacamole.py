import requests
from config import Config
from datetime import datetime

GUACAMOLE_API_URL = Config.GUACAMOLE_API_URL
GUACAMOLE_USERNAME = Config.GUACAMOLE_USERNAME
GUACAMOLE_PASSWORD = Config.GUACAMOLE_PASSWORD

def guacamole_login():
    # Authenticate with Guacamole API and get token
    auth_url = f'{GUACAMOLE_API_URL}/tokens'
    data = {
        'username': GUACAMOLE_USERNAME,
        'password': GUACAMOLE_PASSWORD
    }
    response = requests.post(auth_url, data=data)
    response.raise_for_status()
    token = response.json()['authToken']
    return token

def ensure_all_users_group(token, data_source="mysql"):
    group_name = 'all_users'
    group_url = f'{GUACAMOLE_API_URL}/session/data/{data_source}/userGroups/{group_name}?token={token}'
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.get(group_url, headers=headers)
    if response.status_code == 200:
        # Group exists
        return
    elif response.status_code == 404:
        # Group does not exist, create it
        groups_url = f'{GUACAMOLE_API_URL}/session/data/{data_source}/userGroups?token={token}'
        group_data = {
            "identifier": group_name,
            "attributes": {
                "disabled": "",
                "expired": "",
                "valid-from": "",
                "valid-until": "",
                "timezone": ""
            }
        }
        response = requests.post(groups_url, json=group_data, headers=headers)
        response.raise_for_status()
    else:
        # Some other error
        response.raise_for_status()

def add_user_to_group(token, username, group_name, data_source="mysql"):
    url = f'{GUACAMOLE_API_URL}/session/data/{data_source}/userGroups/{group_name}/memberUsers?token={token}'
    headers = {
        'Content-Type': 'application/json'
    }
    data = [
        {
            "op": "add",
            "path": "/",
            "value": username
        }
    ]
    response = requests.patch(url, json=data, headers=headers)
    response.raise_for_status()

def remove_user_from_group(token, username, group_name, data_source="mysql"):
    url = f'{GUACAMOLE_API_URL}/session/data/{data_source}/userGroups/{group_name}/memberUsers?token={token}'
    headers = {
        'Content-Type': 'application/json'
    }
    data = [
        {
            "op": "remove",
            "path": f"/{username}"
        }
    ]
    response = requests.patch(url, json=data, headers=headers)
    response.raise_for_status()

def grant_group_permission_on_connection(token, group_name, connection_id, data_source="mysql"):
    url = f'{GUACAMOLE_API_URL}/session/data/{data_source}/userGroups/{group_name}/permissions?token={token}'
    headers = {
        'Content-Type': 'application/json'
    }
    data = [
        {
            "op": "add",
            "path": f"/connectionPermissions/{connection_id}",
            "value": "READ"
        }
    ]
    response = requests.patch(url, json=data, headers=headers)
    response.raise_for_status()

def delete_guacamole_connection(token, connection_id, data_source="mysql"):
    # Delete a connection in Guacamole
    connections_url = f'{GUACAMOLE_API_URL}/session/data/{data_source}/connections/{connection_id}?token={token}'
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.delete(connections_url, headers=headers)
    response.raise_for_status()
    
def create_guacamole_user_if_not_exists(token, username, password, data_source="mysql"):
    users_url = f'{GUACAMOLE_API_URL}/session/data/{data_source}/users/{username}?token={token}'
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.get(users_url, headers=headers)
    if response.status_code == 200:
        # User exists
        return
    elif response.status_code == 404:
        # User does not exist, create it
        create_guacamole_user(token, username, password)
    else:
        response.raise_for_status()

def create_guacamole_user(token, username, password, data_source="mysql"):
    # Create a new user in Guacamole
    users_url = f'{GUACAMOLE_API_URL}/session/data/{data_source}/users?token={token}'
    user_data = {
        "username": username,
        "password": password,
        "attributes": {
            "disabled": "",
            "expired": "",
            "access-window-start": "",
            "access-window-end": "",
            "valid-from": "",
            "valid-until": "",
            "timezone": ""
        }
    }
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.post(users_url, json=user_data, headers=headers)
    response.raise_for_status()
    return response.json()

def delete_guacamole_user(token, username, data_source="mysql"):
    # Delete a user in Guacamole
    users_url = f'{GUACAMOLE_API_URL}/session/data/{data_source}/users/{username}?token={token}'
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.delete(users_url, headers=headers)
    response.raise_for_status()
    
def ensure_admins_group(token, data_source="mysql"):
    group_name = 'admins'
    group_url = f'{GUACAMOLE_API_URL}/session/data/{data_source}/userGroups/{group_name}?token={token}'
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.get(group_url, headers=headers)
    if response.status_code == 200:
        # Group exists
        return
    elif response.status_code == 404:
        # Group does not exist, create it
        groups_url = f'{GUACAMOLE_API_URL}/session/data/{data_source}/userGroups?token={token}'
        group_data = {
            "identifier": group_name,
            "attributes": {
                "disabled": "",
                "expired": "",
                "valid-from": "",
                "valid-until": "",
                "timezone": ""
            }
        }
        response = requests.post(groups_url, json=group_data, headers=headers)
        response.raise_for_status()
    else:
        # Some other error
        response.raise_for_status()

def grant_user_permission_on_connection(token, username, connection_id, data_source="mysql"):
    url = f'{GUACAMOLE_API_URL}/session/data/{data_source}/users/{username}/permissions?token={token}'
    headers = {
        'Content-Type': 'application/json'
    }
    data = [
        {
            "op": "add",
            "path": f"/connectionPermissions/{connection_id}",
            "value": "READ"
        }
    ]
    response = requests.patch(url, json=data, headers=headers)
    response.raise_for_status()

def create_guacamole_connection(token, connection_name, ip_address, password, data_source="mysql"):
    # Create a new VNC connection in Guacamole
    connections_url = f'{GUACAMOLE_API_URL}/session/data/{data_source}/connections?token={token}'

    # Extract hostname and port from the IP address
    # Assuming IP address is in the format 'hostname:port'
    hostname, port = ip_address.split(':')

    # Connection parameters
    parameters = {
        "parentIdentifier": "ROOT",
        "name": connection_name,
        "protocol": "vnc",
        "parameters": {
            "hostname": hostname,
            "port": str(port),
            "password": str(password),
            "username": "",  # Add empty username for VNC auth
            "security": "vnc",  # Explicitly set VNC security type
            "ignore-cert": "true",  # Ignore certificate verification
            "clipboard-encoding": "UTF-8",
            "disable-copy": "true",
            "disable-paste": "true",
            "recording-exclude-output": "true",
            "recording-exclude-mouse": "true",
            "recording-include-keys": "",
            "create-recording-path": "",
            "enable-sftp": "",
            "sftp-disable-download": "true",
            "sftp-disable-upload": "true",
            "enable-audio": "false",
            "color-depth": "24",  # Set color depth explicitly
            "swap-red-blue": "",
            "cursor": "local",  # Use local cursor
            "force-lossless": ""
        },
        "attributes": {
            "max-connections": "1",
            "max-connections-per-user": "1",
            "weight": "",
            "failover-only": "",
            "guacd-port": "",
            "guacd-encryption": "",
            "guacd-hostname": ""
        }
    }

    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.post(connections_url, json=parameters, headers=headers)
    response.raise_for_status()
    return response.json()['identifier']  # Return just the connection ID
