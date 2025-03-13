"""Rancher core module for desktop-manager-api.

This module provides data classes for Rancher deployments.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional

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
    image_pull_policy: str = "Always"
    service_type: str = "NodePort"
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
            "imagePullPolicy": self.image_pull_policy,
            "serviceType": self.service_type,
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
        }
        return values
