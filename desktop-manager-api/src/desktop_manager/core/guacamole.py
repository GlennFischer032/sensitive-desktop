import requests
from typing import Optional, Dict, Any, TypedDict, Literal, List, Union, NotRequired
from desktop_manager.config.settings import get_settings
from desktop_manager.core.exceptions import GuacamoleError
import logging

logger = logging.getLogger(__name__)

class GuacamoleUserAttributes(TypedDict, total=False):
    """Type definition for Guacamole user attributes."""
    guac_full_name: str
    guac_organization: str
    expired: str
    disabled: str
    access_window_start: str
    access_window_end: str
    valid_from: str
    valid_until: str
    timezone: Optional[str]

class GuacamoleUser(TypedDict):
    """Type definition for Guacamole user."""
    username: str
    password: str
    attributes: GuacamoleUserAttributes

class GuacamoleGroup(TypedDict):
    """Type definition for Guacamole group."""
    identifier: str
    attributes: GuacamoleUserAttributes

class GuacamoleConnectionParameters(TypedDict):
    """Type definition for Guacamole connection parameters."""
    hostname: str
    port: str
    password: str
    enable_audio: str
    read_only: NotRequired[str]
    swap_red_blue: NotRequired[str]
    cursor: NotRequired[str]
    color_depth: NotRequired[str]
    force_lossless: NotRequired[str]
    clipboard_encoding: NotRequired[str]
    disable_copy: NotRequired[str]
    disable_paste: NotRequired[str]
    dest_port: NotRequired[str]
    recording_exclude_output: NotRequired[str]
    recording_exclude_mouse: NotRequired[str]
    recording_include_keys: NotRequired[str]
    create_recording_path: NotRequired[str]
    enable_sftp: NotRequired[str]
    sftp_port: NotRequired[str]
    sftp_server_alive_interval: NotRequired[str]
    sftp_disable_download: NotRequired[str]
    sftp_disable_upload: NotRequired[str]
    wol_send_packet: NotRequired[str]
    wol_udp_port: NotRequired[str]
    wol_wait_time: NotRequired[str]

class GuacamoleConnectionAttributes(TypedDict, total=False):
    """Type definition for Guacamole connection attributes."""
    max_connections: str
    max_connections_per_user: str
    weight: str
    failover_only: str
    guacd_hostname: str
    guacd_port: str
    guacd_encryption: str

class GuacamoleConnection(TypedDict):
    """Type definition for Guacamole connection."""
    name: str
    identifier: str
    parentIdentifier: str
    protocol: Literal["vnc"]
    attributes: GuacamoleConnectionAttributes
    activeConnections: int
    lastActive: int
    parameters: GuacamoleConnectionParameters

class GuacamolePatchOperation(TypedDict):
    """Type definition for Guacamole PATCH operation."""
    op: Literal["add", "remove"]
    path: str
    value: Union[str, None]

class GuacamoleAuthResponse(TypedDict):
    """Type definition for Guacamole authentication response."""
    authToken: str

class GuacamoleConnectionResponse(TypedDict):
    """Type definition for Guacamole connection response."""
    identifier: str

class GuacamoleUsersResponse(TypedDict):
    """Type definition for Guacamole users response."""
    username: str
    lastActive: int
    attributes: GuacamoleUserAttributes

class GuacamoleClient:
    """
    Client for interacting with the Guacamole API.
    
    This class handles all interactions with the Guacamole API, including
    authentication, user management, and connection management.
    
    Attributes:
        api_url (str): Base URL for the Guacamole API
        username (str): Admin username for Guacamole
        password (str): Admin password for Guacamole
        data_source (str): Guacamole data source (default: "mysql")
    """
    
    def __init__(
        self,
        api_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        data_source: str = "mysql"
    ) -> None:
        """
        Initialize the Guacamole client.
        
        Args:
            api_url: Base URL for the Guacamole API
            username: Admin username for Guacamole
            password: Admin password for Guacamole
            data_source: Guacamole data source
        """
        settings = get_settings()
        self.api_url: str = api_url or settings.GUACAMOLE_API_URL
        self.username: str = username or settings.GUACAMOLE_USERNAME
        self.password: str = password or settings.GUACAMOLE_PASSWORD
        self.data_source: str = data_source
        
    def login(self) -> str:
        """
        Authenticate with the Guacamole API.
        
        Returns:
            Authentication token
            
        Raises:
            GuacamoleError: If authentication fails
        """
        try:
            response: requests.Response = requests.post(
                f"{self.api_url}/tokens",
                data={
                    "username": self.username,
                    "password": self.password
                }
            )
            response.raise_for_status()
            data: GuacamoleAuthResponse = response.json()
            return data["authToken"]
        except Exception as e:
            logger.error(f"Failed to authenticate with Guacamole: {str(e)}")
            raise GuacamoleError("Failed to authenticate with Guacamole")
            
    def create_user(self, token: str, username: str, password: str) -> None:
        """
        Create a new user in Guacamole.
        
        Args:
            token: Authentication token
            username: Username for the new user
            password: Password for the new user
            
        Raises:
            GuacamoleError: If user creation fails
        """
        try:
            user_data: GuacamoleUser = {
                "username": username,
                "password": password,
                "attributes": {
                    "guac_full_name": username,
                    "guac_organization": "Desktop Manager",
                    "expired": "",
                    "disabled": "",
                    "access_window_start": "",
                    "access_window_end": "",
                    "valid_from": "",
                    "valid_until": "",
                    "timezone": None
                }
            }
            response: requests.Response = requests.post(
                f"{self.api_url}/session/data/{self.data_source}/users?token={token}",
                json=user_data
            )
            response.raise_for_status()
        except Exception as e:
            logger.error(f"Failed to create user in Guacamole: {str(e)}")
            raise GuacamoleError(f"Failed to create user in Guacamole: {str(e)}")
            
    def delete_user(self, token: str, username: str) -> None:
        """
        Delete a user from Guacamole.
        
        Args:
            token: Authentication token
            username: Username to delete
            
        Raises:
            GuacamoleError: If user deletion fails
        """
        try:
            response = requests.delete(
                f"{self.api_url}/session/data/{self.data_source}/users/{username}?token={token}"
            )
            response.raise_for_status()
        except Exception as e:
            logger.error(f"Failed to delete user from Guacamole: {str(e)}")
            raise GuacamoleError(f"Failed to delete user from Guacamole: {str(e)}")
            
    def ensure_group(self, token: str, group_name: str) -> None:
        """
        Ensure a group exists in Guacamole, creating it if necessary.
        
        Args:
            token: Authentication token
            group_name: Name of the group to ensure
            
        Raises:
            GuacamoleError: If group creation fails
        """
        try:
            response: requests.Response = requests.get(
                f"{self.api_url}/session/data/{self.data_source}/userGroups/{group_name}?token={token}"
            )
            
            if response.status_code == 404:
                group_data: GuacamoleGroup = {
                    "identifier": group_name,
                    "attributes": {
                        "disabled": "",
                        "expired": "",
                        "valid_from": "",
                        "valid_until": "",
                        "timezone": None
                    }
                }
                response = requests.post(
                    f"{self.api_url}/session/data/{self.data_source}/userGroups?token={token}",
                    json=group_data
                )
                response.raise_for_status()
                logger.info(f"Created group {group_name} in Guacamole")
            elif response.status_code != 200:
                response.raise_for_status()
                
        except Exception as e:
            logger.error(f"Failed to ensure group in Guacamole: {str(e)}")
            raise GuacamoleError(f"Failed to ensure group in Guacamole: {str(e)}")
            
    def add_user_to_group(self, token: str, username: str, group_name: str) -> None:
        """
        Add a user to a group in Guacamole.
        
        Args:
            token: Authentication token
            username: Username to add to group
            group_name: Name of the group
            
        Raises:
            GuacamoleError: If adding user to group fails
        """
        try:
            patch_data: List[GuacamolePatchOperation] = [{
                "op": "add",
                "path": "/",
                "value": username
            }]
            response: requests.Response = requests.patch(
                f"{self.api_url}/session/data/{self.data_source}/userGroups/{group_name}/memberUsers?token={token}",
                json=patch_data
            )
            response.raise_for_status()
        except Exception as e:
            logger.error(f"Failed to add user to group in Guacamole: {str(e)}")
            raise GuacamoleError(f"Failed to add user to group in Guacamole: {str(e)}")
            
    def remove_user_from_group(self, token: str, username: str, group_name: str) -> None:
        """
        Remove a user from a group in Guacamole.
        
        Args:
            token: Authentication token
            username: Username to remove from group
            group_name: Name of the group
            
        Raises:
            GuacamoleError: If removing user from group fails
        """
        try:
            response = requests.patch(
                f"{self.api_url}/session/data/{self.data_source}/userGroups/{group_name}/memberUsers?token={token}",
                json=[{
                    "op": "remove",
                    "path": f"/{username}"
                }]
            )
            response.raise_for_status()
        except Exception as e:
            logger.error(f"Failed to remove user from group in Guacamole: {str(e)}")
            raise GuacamoleError(f"Failed to remove user from group in Guacamole: {str(e)}")
            
    def get_users(self, token: str) -> Dict[str, GuacamoleUsersResponse]:
        """
        Get all users from Guacamole.
        
        Args:
            token: Authentication token
            
        Returns:
            Dictionary of user information
            
        Raises:
            GuacamoleError: If getting users fails
        """
        try:
            response: requests.Response = requests.get(
                f"{self.api_url}/session/data/{self.data_source}/users?token={token}"
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get users from Guacamole: {str(e)}")
            raise GuacamoleError(f"Failed to get users from Guacamole: {str(e)}")

# For backward compatibility
def guacamole_login() -> str:
    """Backward compatibility function for guacamole login."""
    client = GuacamoleClient()
    return client.login()

def create_guacamole_user(token: str, username: str, password: str) -> None:
    """Backward compatibility function for creating a user."""
    client = GuacamoleClient()
    client.create_user(token, username, password)

def delete_guacamole_user(token: str, username: str) -> None:
    """Backward compatibility function for deleting a user."""
    client = GuacamoleClient()
    client.delete_user(token, username)

def ensure_all_users_group(token: str) -> None:
    """Backward compatibility function for ensuring all_users group."""
    client = GuacamoleClient()
    client.ensure_group(token, "all_users")

def ensure_admins_group(token: str) -> None:
    """Backward compatibility function for ensuring admins group."""
    client = GuacamoleClient()
    client.ensure_group(token, "admins")

def add_user_to_group(token: str, username: str, group_name: str) -> None:
    """Backward compatibility function for adding user to group."""
    client = GuacamoleClient()
    client.add_user_to_group(token, username, group_name)

def remove_user_from_group(token: str, username: str, group_name: str) -> None:
    """Backward compatibility function for removing user from group."""
    client = GuacamoleClient()
    client.remove_user_from_group(token, username, group_name)

def grant_group_permission_on_connection(token: str, group_name: str, connection_id: str, data_source: str = "mysql") -> None:
    """
    Grant READ permission to a group on a connection.
    
    Args:
        token: Authentication token
        group_name: Name of the group
        connection_id: ID of the connection
        data_source: Guacamole data source
        
    Raises:
        GuacamoleError: If granting permission fails
    """
    client = GuacamoleClient(data_source=data_source)
    try:
        response = requests.patch(
            f"{client.api_url}/session/data/{data_source}/userGroups/{group_name}/permissions?token={token}",
            json=[{
                "op": "add",
                "path": f"/connectionPermissions/{connection_id}",
                "value": "READ"
            }]
        )
        response.raise_for_status()
    except Exception as e:
        logger.error(f"Failed to grant group permission on connection: {str(e)}")
        raise GuacamoleError(f"Failed to grant group permission on connection: {str(e)}")

def delete_guacamole_connection(token: str, connection_id: str, data_source: str = "mysql") -> None:
    """
    Delete a connection from Guacamole.
    
    Args:
        token: Authentication token
        connection_id: ID of the connection to delete
        data_source: Guacamole data source
        
    Raises:
        GuacamoleError: If connection deletion fails
    """
    client = GuacamoleClient(data_source=data_source)
    try:
        response = requests.delete(
            f"{client.api_url}/session/data/{data_source}/connections/{connection_id}?token={token}"
        )
        response.raise_for_status()
    except Exception as e:
        logger.error(f"Failed to delete Guacamole connection: {str(e)}")
        raise GuacamoleError(f"Failed to delete Guacamole connection: {str(e)}")
    
def create_guacamole_user_if_not_exists(token: str, username: str, password: str, data_source: str = "mysql") -> None:
    """
    Create a user in Guacamole if they don't already exist.
    
    Args:
        token: Authentication token
        username: Username to create
        password: Password for the user
        data_source: Guacamole data source
        
    Raises:
        GuacamoleError: If user creation fails
    """
    client = GuacamoleClient(data_source=data_source)
    try:
        # Check if user exists
        response = requests.get(
            f"{client.api_url}/session/data/{data_source}/users/{username}?token={token}"
        )
        
        if response.status_code == 404:
            # User doesn't exist, create them
            client.create_user(token, username, password)
        elif response.status_code != 200:
            response.raise_for_status()
            
    except Exception as e:
        logger.error(f"Failed to check/create Guacamole user: {str(e)}")
        raise GuacamoleError(f"Failed to check/create Guacamole user: {str(e)}")

def grant_user_permission_on_connection(
    token: str,
    username: str,
    connection_id: str,
    data_source: str = "mysql"
) -> None:
    """
    Grant READ permission to a user on a connection.
    
    Args:
        token: Authentication token
        username: Username to grant permission to
        connection_id: ID of the connection
        data_source: Guacamole data source
        
    Raises:
        GuacamoleError: If granting permission fails
    """
    client = GuacamoleClient(data_source=data_source)
    try:
        patch_data: List[GuacamolePatchOperation] = [{
            "op": "add",
            "path": f"/connectionPermissions/{connection_id}",
            "value": "READ"
        }]
        
        response: requests.Response = requests.patch(
            f"{client.api_url}/session/data/{data_source}/users/{username}/permissions?token={token}",
            json=patch_data
        )
        response.raise_for_status()
    except Exception as e:
        logger.error(f"Failed to grant user permission on connection: {str(e)}")
        raise GuacamoleError(f"Failed to grant user permission on connection: {str(e)}")

def create_guacamole_connection(
    token: str,
    connection_name: str,
    ip_address: str,
    password: str,
    data_source: str = "mysql"
) -> str:
    """
    Create a new connection in Guacamole.
    
    Args:
        token: Authentication token
        connection_name: Name of the connection
        ip_address: IP address or hostname of the VNC server
        password: VNC password
        data_source: Guacamole data source
        
    Returns:
        ID of the created connection
        
    Raises:
        GuacamoleError: If connection creation fails
    """
    client = GuacamoleClient(data_source=data_source)
    try:
        connection_data: GuacamoleConnection = {
            "name": connection_name,
            "parentIdentifier": "ROOT",
            "protocol": "vnc",
            "activeConnections": 0,
            "parameters": {
                "hostname": ip_address,
                "password": password,
                "enable_audio": "true",
                "port": "5900",
                "read-only": "",
                "swap-red-blue": "",
                "cursor": "",
                "color-depth": "",
                "force-lossless": "",
                "clipboard-encoding": "",
                "disable-copy": "true",
                "disable-paste": "",
                "dest-port": "",
                "recording-exclude-output": "true",
                "recording-exclude-mouse": "true",
                "recording-include-keys": "true",
                "create-recording-path": "",
                "enable-sftp": "",
                "sftp-port": "",
                "sftp-server-alive-interval": "",
                "sftp-disable-download": "true",
                "sftp-disable-upload": "true",
                "enable-audio": "",
                "wol-send-packet": "",
                "wol-udp-port": "",
                "wol-wait-time": ""
            },
            "attributes": {
                "guacd-encryption": "",
                "failover-only": "",
                "weight": "",
                "max-connections": "",
                "guacd-hostname": None,
                "guacd-port": "",
                "max-connections-per-user": ""
            }
        }
        
        response: requests.Response = requests.post(
            f"{client.api_url}/session/data/{data_source}/connections?token={token}",
            json=connection_data
        )
        response.raise_for_status()
        data: GuacamoleConnectionResponse = response.json()
        return data["identifier"]
    except Exception as e:
        logger.error(f"Failed to create Guacamole connection: {str(e)}")
        raise GuacamoleError(f"Failed to create Guacamole connection: {str(e)}")
