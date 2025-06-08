"""Rancher client module for desktop-manager-api.

This module provides a client for managing Rancher deployments.
"""

from dataclasses import dataclass
import logging
import os
import subprocess
import tempfile
import time
from typing import Any

from clients.base import APIError, BaseClient
from config.settings import get_settings
import requests
import yaml


@dataclass
class WebRTCImages:
    """WebRTC images configuration for desktop deployments."""

    xserver: str = "cerit.io/desktops/xserver:v0.3"
    pulseaudio: str = "cerit.io/desktops/pulseaudio:v0.1"
    gstreamer: str = "cerit.io/desktops/webrtc-app:1.20.1-nv"
    web: str = "cerit.io/desktops/webrtc-web:0.6"


@dataclass
class Storage:
    """Storage configuration for desktop deployments."""

    enable: bool = False
    server: str = ""
    username: str = ""
    password: str = ""
    externalpvc: dict[str, Any] = None
    persistenthome: bool = True

    def __post_init__(self):
        if self.externalpvc is None:
            self.externalpvc = {"enable": False, "name": ""}

    def use_external_pvc(self, pvc_name: str):
        """Configure storage to use an external PVC.

        Args:
            pvc_name: Name of the PVC to use
        """
        self.externalpvc = {"enable": True, "name": pvc_name}


@dataclass
class DesktopValues:
    """Values for desktop deployment configuration."""

    desktop: str = "cerit.io/desktops/ubuntu-xfce:22.04-user"
    name: str = None
    webrtcimages: WebRTCImages = None
    mincpu: int = 1
    maxcpu: int = 4
    minram: str = "4096Mi"
    maxram: str = "16384Mi"
    username: str = "user"
    resolution: str = "1920x1080"
    display: str = "VNC"
    storage: Storage = None
    vnc_password: str = None
    external_pvc: str | None = None
    persistent_home: bool = True
    guacamole: dict[str, Any] = None

    def __post_init__(self):
        self.webrtcimages = WebRTCImages()
        if self.storage is None:
            self.storage = Storage()
        if self.guacamole is None:
            self.guacamole = {"namespace": "", "releaseName": ""}
        # If external_pvc is provided, configure storage to use it
        if self.external_pvc:
            self.storage.use_external_pvc(self.external_pvc)

        # If persistent_home is False, disable storage
        if not self.persistent_home:
            self.storage.enable = False

    def to_dict(self) -> dict:
        values = {
            "desktop": self.desktop,
            "webrtcimages": {
                "xserver": self.webrtcimages.xserver,
                "pulseaudio": self.webrtcimages.pulseaudio,
                "gstreamer": self.webrtcimages.gstreamer,
                "web": self.webrtcimages.web,
            },
            "mincpu": self.mincpu,
            "maxcpu": self.maxcpu,
            "minram": self.minram,
            "maxram": self.maxram,
            "username": self.username,
            "password": self.vnc_password,
            "resolution": self.resolution,
            "display": self.display,
            "storage": {
                "enable": self.storage.enable,
                "server": self.storage.server,
                "username": self.storage.username,
                "password": self.storage.password,
                "externalpvc": self.storage.externalpvc,
                "persistenthome": self.storage.persistenthome,
            },
            "guacamole": self.guacamole,
        }
        return values


class RancherClient(BaseClient):
    """Client for managing Rancher deployments.

    This client provides methods for:
    - Installing Helm charts via Rancher API
    - Uninstalling Helm charts via Rancher API
    - Checking if VNC server is ready
    - Getting pod IP addresses
    """

    def __init__(
        self,
        api_url: str | None = None,
        api_token: str | None = None,
        cluster_id: str | None = None,
        cluster_name: str | None = None,
        project_id: str | None = None,
        repo_name: str | None = None,
        namespace: str | None = None,
    ):
        """Initialize RancherClient.

        Args:
            api_url: Rancher API URL
            api_token: Rancher API token
            cluster_id: Rancher cluster ID
            cluster_name: Rancher cluster name
            project_id: Rancher project ID
            repo_name: Repository name
            namespace: Kubernetes namespace
        """
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        settings = get_settings()
        self.api_url = api_url or settings.RANCHER_API_URL
        self.api_token = api_token or settings.RANCHER_API_TOKEN
        self.cluster_id = cluster_id or settings.RANCHER_CLUSTER_ID
        self.cluster_name = cluster_name or settings.RANCHER_CLUSTER_NAME
        self.project_id = project_id or settings.RANCHER_PROJECT_ID
        self.repo_name = repo_name or settings.RANCHER_REPO_NAME
        self.namespace = namespace or settings.NAMESPACE
        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }

    def install(self, connection_name: str, values: DesktopValues) -> dict[str, Any]:
        """Install a Helm chart using local chart via helm CLI.

        Args:
            connection_name: Connection name
            values: Desktop values

        Returns:
            Dict[str, Any]: Response data

        Raises:
            APIError: If Helm chart installation fails
        """
        try:
            # Input validation for security
            if not connection_name or not connection_name.replace("-", "").replace("_", "").isalnum():
                error_message = "Invalid connection_name: must be alphanumeric with hyphens/underscores only"
                self.logger.error(error_message)
                raise APIError(error_message, status_code=400)

            # Path to the local helm chart and kubeconfig
            chart_path = os.path.abspath("src/desktop_charts/default")
            kubeconfig_path = os.path.abspath("src/desktop_charts/config")

            self.logger.debug("Using chart path: %s (exists: %s)", chart_path, os.path.exists(chart_path))

            if not os.path.exists(chart_path):
                # Debug current directory structure
                cwd = os.getcwd()
                self.logger.error("Chart not found. CWD: %s, Contents: %s", cwd, os.listdir(cwd))
                raise APIError("Desktop chart not found at expected location", status_code=500)

            # Prepare helm install command with validated inputs
            helm_cmd = [
                "helm",
                "install",
                connection_name,  # subprocess handles escaping automatically
                chart_path,  # static path
                "--namespace",
                self.namespace,  # subprocess handles escaping automatically
                "--wait",
                "--timeout",
                "600s",
            ]

            # Use kubeconfig only if it exists, otherwise assume in-cluster config
            if os.path.exists(kubeconfig_path):
                self.logger.debug("Using kubeconfig path: %s", kubeconfig_path)
                helm_cmd.extend(["--kubeconfig", kubeconfig_path])
            else:
                self.logger.info("Kubeconfig not found, assuming in-cluster config for Helm.")

            # Create temporary values file
            values_dict = values.to_dict()
            with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as values_file:
                yaml.dump(values_dict, values_file, default_flow_style=False)
                values_file_path = values_file.name

            # Add values file to command
            helm_cmd.extend(["--values", values_file_path])

            self.logger.debug(
                "Installing Helm chart via helm CLI: %s (chart: %s, namespace: %s, kubeconfig: %s)",
                connection_name,
                chart_path,
                self.namespace,
                kubeconfig_path,
            )

            # Log the full command for debugging
            self.logger.debug("Executing helm command: %s", " ".join(helm_cmd))

            # Execute helm install command - inputs are validated above
            result = subprocess.run(
                helm_cmd,
                capture_output=True,
                text=True,
                timeout=630,  # Slightly longer than helm timeout
                check=False,
            )

            # Clean up temporary values file
            try:
                os.unlink(values_file_path)
            except OSError as cleanup_error:
                self.logger.warning("Failed to clean up temporary values file: %s", cleanup_error)

            if result.returncode != 0:
                error_message = f"Failed to install Helm chart: {result.stderr}"
                self.logger.error(error_message)
                raise APIError(error_message, status_code=500)

            self.logger.debug("Helm chart installation successful: %s", result.stdout)

            # Return a response similar to the original API response
            return {
                "status": "success",
                "release_name": connection_name,
                "namespace": self.namespace,
                "chart_path": chart_path,
                "output": result.stdout,
            }

        except subprocess.TimeoutExpired as e:
            error_message = f"Helm installation timed out: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e
        except subprocess.SubprocessError as e:
            error_message = f"Failed to install Helm chart: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e
        except Exception as e:
            error_message = f"Unexpected error installing Helm chart: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def uninstall(self, connection_name: str) -> dict[str, Any]:
        """Uninstall a Helm chart using helm CLI.

        Args:
            connection_name: Connection name

        Returns:
            Dict[str, Any]: Response data

        Raises:
            APIError: If Helm chart uninstallation fails
        """
        try:
            # Input validation for security
            if not connection_name or not connection_name.replace("-", "").replace("_", "").isalnum():
                error_message = "Invalid connection_name: must be alphanumeric with hyphens/underscores only"
                self.logger.error(error_message)
                raise APIError(error_message, status_code=400)

            # Path to the kubeconfig
            kubeconfig_path = os.path.abspath("src/desktop_charts/config")

            # Prepare helm uninstall command
            helm_cmd = [
                "helm",
                "uninstall",
                connection_name,
                "--namespace",
                self.namespace,
                "--wait",
                "--timeout",
                "600s",
            ]

            # Use kubeconfig only if it exists, otherwise assume in-cluster config
            if os.path.exists(kubeconfig_path):
                self.logger.debug("Using kubeconfig path: %s", kubeconfig_path)
                helm_cmd.extend(["--kubeconfig", kubeconfig_path])
            else:
                self.logger.info("Kubeconfig not found, assuming in-cluster config for Helm.")

            self.logger.debug(
                "Uninstalling Helm chart via helm CLI: %s (namespace: %s)",
                connection_name,
                self.namespace,
            )
            # Log the full command for debugging
            self.logger.debug("Executing helm command: %s", " ".join(helm_cmd))

            # Execute helm uninstall command
            result = subprocess.run(
                helm_cmd,
                capture_output=True,
                text=True,
                timeout=630,  # Slightly longer than helm timeout
                check=False,
            )

            if result.returncode != 0:
                # If the release is not found, it's a successful uninstallation for our purposes.
                if "not found" in result.stderr:
                    self.logger.warning("Release '%s' not found, assuming already uninstalled.", connection_name)
                    return {"status": "success", "message": "Release not found."}

                error_message = f"Failed to uninstall Helm chart: {result.stderr}"
                self.logger.error(error_message)
                raise APIError(error_message, status_code=500)

            self.logger.debug("Helm chart uninstallation successful: %s", result.stdout)

            # Return a response similar to the original API response
            return {
                "status": "success",
                "release_name": connection_name,
                "namespace": self.namespace,
                "output": result.stdout,
            }

        except subprocess.TimeoutExpired as e:
            error_message = f"Helm uninstallation timed out: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e
        except subprocess.SubprocessError as e:
            error_message = f"Failed to uninstall Helm chart: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e
        except Exception as e:
            error_message = f"Unexpected error uninstalling Helm chart: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def check_vnc_ready(self, connection_name: str, max_retries: int = 60, retry_interval: int = 3) -> bool:
        """Check if VNC server pod is ready and VNC port is accessible.

        Args:
            connection_name: Connection name
            max_retries: Maximum number of retry attempts (default: 60)
            retry_interval: Time to wait between retries in seconds (default: 2)

        Returns:
            bool: True if VNC server is ready, False otherwise

        Raises:
            APIError: If checking VNC readiness fails
        """
        try:
            for attempt in range(max_retries):
                try:
                    pods = self.list_pods()

                    # Log all pod names for debugging
                    pod_names = [pod["metadata"]["name"] for pod in pods]
                    self.logger.debug("Found pods in namespace: %s", pod_names)

                    # Check if the desktop pod exists and is ready
                    desktop_pod = None
                    for pod in pods:
                        pod_name = pod["metadata"]["name"]
                        # The pod name format is {connection_name}-0
                        if pod_name == f"{connection_name}-0":
                            desktop_pod = pod
                            self.logger.debug("Found desktop pod: %s", pod_name)
                            break

                    if not desktop_pod:
                        self.logger.warning(
                            "Desktop pod for %s not found, retrying (%s/%s)",
                            connection_name,
                            attempt + 1,
                            max_retries,
                        )
                        time.sleep(retry_interval)
                        continue

                    # Check if pod is ready
                    status = desktop_pod.get("status", {})
                    phase = status.get("phase")
                    container_statuses = status.get("containerStatuses", [])

                    if phase != "Running":
                        self.logger.warning(
                            "Desktop pod for %s is not running (phase: %s), retrying (%s/%s)",
                            connection_name,
                            phase,
                            attempt + 1,
                            max_retries,
                        )
                        time.sleep(retry_interval)
                        continue

                    # Check if all containers are ready
                    all_ready = all(container.get("ready", False) for container in container_statuses)
                    if not all_ready:
                        self.logger.warning(
                            "Not all containers in pod for %s are ready, retrying (%s/%s)",
                            connection_name,
                            attempt + 1,
                            max_retries,
                        )
                        time.sleep(retry_interval)
                        continue

                    self.logger.info("Desktop pod for %s is ready", connection_name)
                    return True

                except Exception as e:
                    self.logger.error("Error checking pod status: %s", str(e))
                    time.sleep(retry_interval)

            self.logger.error(
                "Desktop pod for %s failed to become ready after %s attempts",
                connection_name,
                max_retries,
            )
            return False
        except Exception as e:
            error_message = f"Unexpected error checking VNC readiness: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def check_release_uninstalled(self, connection_name: str, max_retries: int = 60, retry_interval: int = 2) -> bool:
        """Check if a Helm release is uninstalled.

        Args:
            connection_name: Connection name
            max_retries: Maximum number of retry attempts (default: 60)
            retry_interval: Time to wait between retries in seconds (default: 2)

        Returns:
            bool: True if release is uninstalled, False otherwise

        Raises:
            APIError: If checking release uninstallation fails
        """
        try:
            # First verify that the release and pod are gone
            for attempt in range(max_retries):
                try:
                    releases = self.list_releases()
                    release_removed = connection_name not in [release["metadata"]["name"] for release in releases]

                    pods = self.list_pods()
                    pod_removed = connection_name + "-0" not in [pod["metadata"]["name"] for pod in pods]

                    if release_removed and pod_removed:
                        # Now perform confirmation checks to ensure uninstallation is truly complete
                        return True
                    elif not release_removed:
                        self.logger.warning(
                            "Release %s not uninstalled, retrying (%s/%s)", connection_name, attempt + 1, max_retries
                        )
                        time.sleep(retry_interval)
                    elif not pod_removed:
                        self.logger.warning(
                            "Pod %s not removed, retrying (%s/%s)", connection_name, attempt + 1, max_retries
                        )
                        time.sleep(retry_interval)
                except Exception as e:
                    self.logger.error("Error checking release status: %s", str(e))
                    time.sleep(retry_interval)

            self.logger.error("Release %s not found after %s attempts", connection_name, max_retries)
            return False
        except Exception as e:
            error_message = f"Unexpected error checking release uninstallation: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def get_pod_ip(self, connection_name: str) -> str | None:
        """Get the IP address of the pod.

        Args:
            connection_name: Connection name

        Returns:
            Optional[str]: Pod IP address

        Raises:
            APIError: If getting pod IP fails
        """
        try:
            url = (
                f"{self.api_url}/k8s/clusters/{self.cluster_id}/v1/pod?namespaceId={self.namespace}"
                f"&labelSelector=app.kubernetes.io%2Finstance%3D{connection_name}"
            )

            self.logger.debug("Getting pod IP for connection: %s", connection_name)
            response = requests.get(url, headers=self.headers, timeout=10)

            if response.status_code >= 400:
                error_message = f"Failed to get pod IP: {response.text}"
                self.logger.error(error_message)
                raise APIError(error_message, status_code=response.status_code)

            pods = response.json().get("data", [])
            for pod in pods:
                status = pod.get("status", {})
                phase = status.get("phase")
                if phase == "Running":
                    pod_ip = status.get("podIP")
                    self.logger.debug("Found pod IP: %s", pod_ip)
                    return pod_ip

            self.logger.warning("No running pod found for connection: %s", connection_name)
            return None
        except requests.RequestException as e:
            error_message = f"Failed to get pod IP: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e
        except Exception as e:
            error_message = f"Unexpected error getting pod IP: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def list_releases(self) -> list[dict[str, Any]]:
        """List Helm releases via Rancher API.

        Returns:
            List[Dict[str, Any]]: List of releases

        Raises:
            APIError: If listing releases fails
        """
        try:
            url = (
                f"{self.api_url}/k8s/clusters/{self.cluster_id}/v1/catalog.cattle.io.apps"
                f"?namespaceId={self.namespace}"
            )

            self.logger.debug("Listing Helm releases via Rancher API")
            response = requests.get(url, headers=self.headers, timeout=10)

            if response.status_code >= 400:
                error_message = f"Failed to list releases: {response.text}"
                self.logger.error(error_message)
                raise APIError(error_message, status_code=response.status_code)

            releases = response.json().get("data", [])
            self.logger.debug("Found %s releases", len(releases))
            return releases
        except requests.RequestException as e:
            error_message = f"Failed to list releases: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e
        except Exception as e:
            error_message = f"Unexpected error listing releases: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def get_release(self, connection_name: str) -> dict[str, Any]:
        """Get a Helm release via Rancher API.

        Args:
            connection_name: Connection name

        Returns:
            Dict[str, Any]: Release data

        Raises:
            APIError: If getting release fails
        """
        try:
            url = (
                f"{self.api_url}/k8s/clusters/{self.cluster_id}/v1/catalog.cattle.io.apps"
                f"/{self.namespace}/{connection_name}"
            )

            self.logger.debug("Getting Helm release via Rancher API: %s", connection_name)
            response = requests.get(url, headers=self.headers, timeout=10)

            if response.status_code >= 400:
                error_message = f"Failed to get release: {response.text}"
                self.logger.error(error_message)
                raise APIError(error_message, status_code=response.status_code)

            self.logger.debug("Got release: %s", connection_name)
            return response.json()
        except requests.RequestException as e:
            error_message = f"Failed to get release: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e
        except Exception as e:
            error_message = f"Unexpected error getting release: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def create_pvc(
        self,
        name: str,
        namespace: str | None = None,
        size: str = "10Gi",
    ) -> dict[str, Any]:
        """Create a Persistent Volume Claim (PVC) via Rancher API.

        Args:
            name: PVC name
            namespace: Kubernetes namespace (defaults to the client's namespace)
            size: Storage size (e.g. '10Gi')

        Returns:
            Dict[str, Any]: Response data

        Raises:
            APIError: If PVC creation fails
        """
        try:
            # Always use ReadWriteMany access mode
            access_modes = ["ReadWriteMany"]

            namespace_to_use = namespace or self.namespace

            # URL for creating PVCs via Rancher API
            url = f"{self.api_url}/k8s/clusters/{self.cluster_id}/v1/persistentvolumeclaims"

            # Payload for PVC creation
            pvc_data = {
                "type": "persistentvolumeclaim",
                "metadata": {"namespace": namespace_to_use, "name": name},
                "spec": {
                    "accessModes": access_modes,
                    "volumeName": "",
                    "resources": {"requests": {"storage": size}},
                },
                "accessModes": access_modes,  # This is required for the Rancher UI
            }

            self.logger.debug(
                "Creating PVC via Rancher API: %s (namespace: %s, size: %s)",
                name,
                namespace_to_use,
                size,
            )
            response = requests.post(url, headers=self.headers, json=pvc_data, timeout=30)

            if response.status_code >= 400:
                error_message = f"Failed to create PVC: {response.text}"
                self.logger.error(error_message)
                raise APIError(error_message, status_code=response.status_code)

            self.logger.debug("PVC creation response: %s", response.status_code)
            return response.json() if response.text else {}
        except requests.RequestException as e:
            error_message = f"Failed to create PVC: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e
        except Exception as e:
            error_message = f"Unexpected error creating PVC: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def get_pvc(self, name: str, namespace: str | None = None) -> dict[str, Any]:
        """Get a Persistent Volume Claim (PVC) via Rancher API.

        Args:
            name: PVC name
            namespace: Kubernetes namespace (defaults to the client's namespace)

        Returns:
            Dict[str, Any]: PVC data

        Raises:
            APIError: If PVC retrieval fails
        """
        try:
            namespace_to_use = namespace or self.namespace

            # URL for getting PVC via Rancher API
            url = (
                f"{self.api_url}/k8s/clusters/{self.cluster_id}/v1/persistentvolumeclaims/" f"{namespace_to_use}/{name}"
            )

            self.logger.debug(
                "Getting PVC via Rancher API: %s (namespace: %s)",
                name,
                namespace_to_use,
            )
            response = requests.get(url, headers=self.headers, timeout=10)

            if response.status_code >= 400:
                error_message = f"Failed to get PVC: {response.text}"
                self.logger.error(error_message)
                raise APIError(error_message, status_code=response.status_code)

            self.logger.debug("Got PVC: %s", name)
            return response.json()
        except requests.RequestException as e:
            error_message = f"Failed to get PVC: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e
        except Exception as e:
            error_message = f"Unexpected error getting PVC: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def delete_pvc(self, name: str, namespace: str | None = None) -> dict[str, Any]:
        """Delete a Persistent Volume Claim (PVC) via Rancher API.

        Args:
            name: PVC name
            namespace: Kubernetes namespace (defaults to the client's namespace)

        Returns:
            Dict[str, Any]: Response data

        Raises:
            APIError: If PVC deletion fails
        """
        try:
            namespace_to_use = namespace or self.namespace

            # URL for deleting PVC via Rancher API
            url = (
                f"{self.api_url}/k8s/clusters/{self.cluster_id}/v1/persistentvolumeclaims/" f"{namespace_to_use}/{name}"
            )

            self.logger.debug(
                "Deleting PVC via Rancher API: %s (namespace: %s)",
                name,
                namespace_to_use,
            )
            response = requests.delete(url, headers=self.headers, timeout=30)

            if response.status_code >= 400:
                error_message = f"Failed to delete PVC: {response.text}"
                self.logger.error(error_message)
                raise APIError(error_message, status_code=response.status_code)

            self.logger.debug("PVC deletion response: %s", response.status_code)
            return response.json() if response.text else {}
        except requests.RequestException as e:
            error_message = f"Failed to delete PVC: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e
        except Exception as e:
            error_message = f"Unexpected error deleting PVC: {e!s}"
            self.logger.error(error_message)
            raise APIError(error_message, status_code=500) from e

    def list_pods(self) -> list[dict[str, Any]]:
        """List all pods in the cluster.

        Returns:
            List[Dict[str, Any]]: List of pods
        """
        try:
            url = f"{self.api_url}/k8s/clusters/{self.cluster_id}/v1/pods"
            response = requests.get(url, headers=self.headers, timeout=10)

            if response.status_code >= 400:
                error_message = f"Failed to list pods: {response.text}"
                self.logger.error(error_message)
                raise APIError(error_message, status_code=response.status_code)

            return response.json().get("data", [])
        except requests.RequestException as e:
            error_message = f"Failed to list pods: {e!s}"
            self.logger.error(error_message)
