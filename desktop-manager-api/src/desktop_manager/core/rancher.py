from dataclasses import dataclass
from typing import Dict, Optional, List, Any
import requests
from desktop_manager.config.settings import get_settings

@dataclass
class WebRTCImages:
    xserver: str = "cerit.io/desktops/xserver:v0.3"
    pulseaudio: str = "cerit.io/desktops/pulseaudio:v0.1"
    gstreamer: str = "cerit.io/desktops/webrtc-app:1.20.1-nv"
    web: str = "cerit.io/desktops/webrtc-web:0.6"

@dataclass
class Storage:
    enable: bool = False
    server: str = ""
    username: str = ""
    password: str = ""
    externalpvc: Dict[str, Any] = None
    persistenthome: bool = True

    def __post_init__(self):
        if self.externalpvc is None:
            self.externalpvc = {"enable": False, "name": ""}

@dataclass
class DesktopValues:
    desktop: str = "cerit.io/desktops/ubuntu-xfce:22.04-user"
    name: str = None
    image: str = None
    imagePullPolicy: str = "Always"
    serviceType: str = "NodePort"
    webrtcimages: WebRTCImages = None
    mincpu: int = 1
    maxcpu: int = 4
    minram: str = "4096Mi"
    maxram: str = "16384Mi"
    username: str = "user"
    resolution: str = "1920x1080"
    display: str = "VNC"
    storage: Storage = None
    vncPassword: str = None

    def __post_init__(self):
        if self.webrtcimages is None:
            self.webrtcimages = WebRTCImages()
        if self.storage is None:
            self.storage = Storage()
        if self.image is None:
            self.image = self.desktop

    def to_dict(self) -> dict:
        values = {
            "name": self.name,
            "image": self.image,
            "imagePullPolicy": self.imagePullPolicy,
            "serviceType": self.serviceType,
            "webrtcimages": {
                "xserver": self.webrtcimages.xserver,
                "pulseaudio": self.webrtcimages.pulseaudio,
                "gstreamer": self.webrtcimages.gstreamer,
                "web": self.webrtcimages.web
            },
            "mincpu": self.mincpu,
            "maxcpu": self.maxcpu,
            "minram": self.minram,
            "maxram": self.maxram,
            "username": self.username,
            "password": self.vncPassword,
            "resolution": self.resolution,
            "display": self.display,
            "storage": {
                "enable": self.storage.enable,
                "server": self.storage.server,
                "username": self.storage.username,
                "password": self.storage.password,
                "externalpvc": self.storage.externalpvc,
                "persistenthome": self.storage.persistenthome
            }
        }
        return values

class RancherAPI:
    def __init__(self, api_url=None, api_token=None, cluster_id=None, repo_name=None, namespace=None):
        settings = get_settings()
        self.api_url = api_url or settings.RANCHER_API_URL
        self.api_token = api_token or settings.RANCHER_API_TOKEN
        self.cluster_id = cluster_id or settings.RANCHER_CLUSTER_ID
        self.repo_name = repo_name or settings.RANCHER_REPO_NAME
        self.namespace = namespace or settings.NAMESPACE

    def install_chart(self, release_name: str, namespace: str, values: DesktopValues) -> requests.Response:
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        }

        payload = {
            "charts": [
                {
                    "chartName": "desktop",
                    "version": "0.4",
                    "releaseName": release_name,
                    "annotations": {
                        "catalog.cattle.io/ui-source-repo-type": "cluster",
                        "catalog.cattle.io/ui-source-repo": self.repo_name
                    },
                    "values": values.to_dict()
                }
            ],
            "noHooks": False,
            "timeout": "600s",
            "wait": True,
            "namespace": namespace,
            "disableOpenAPIValidation": False,
            "skipCRDs": False
        }

        url = f"{self.api_url}/k8s/clusters/{self.cluster_id}/v1/catalog.cattle.io.clusterrepos/{self.repo_name}?action=install"
        
        response = requests.post(url, headers=headers, json=payload)
        print(response.text)
        return response

    def uninstall_chart(self, release_name: str, namespace: str) -> requests.Response:
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        }

        url = f"{self.api_url}/k8s/clusters/{self.cluster_id}/v1/catalog.cattle.io.apps/{namespace}/{release_name}?action=uninstall"
        
        response = requests.post(url, headers=headers, json={})
        print(response.text)
        return response
