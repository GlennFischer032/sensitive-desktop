# config.py

import os


class Config:
    def __init__(self):
        self.SECRET_KEY = os.environ.get("SECRET_KEY", "")

        # PostgreSQL Database settings
        self.POSTGRES_HOST = os.environ.get("POSTGRES_HOST", "localhost")
        self.POSTGRES_PORT = os.environ.get("POSTGRES_PORT", "5432")
        self.POSTGRES_DB = os.environ.get("POSTGRES_DB", "desktop_manager")
        self.POSTGRES_USER = os.environ.get("POSTGRES_USER", "guacamole_user")
        self.POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "")

        # SQLAlchemy URL construction for PostgreSQL
        self.DATABASE_URL = os.environ.get(
            "DATABASE_URL",
            f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}",
        )

        # Guacamole API settings
        self.GUACAMOLE_URL = os.environ.get("GUACAMOLE_URL", "http://localhost:8080/guacamole")
        self.GUACAMOLE_USERNAME = os.environ.get("GUACAMOLE_USERNAME", "")
        self.GUACAMOLE_PASSWORD = os.environ.get("GUACAMOLE_PASSWORD", "")

        # Other settings
        self.NAMESPACE = os.environ.get("NAMESPACE", "")

        # Admin user credentials
        self.ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "")
        self.ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

        # Rancher API settings
        self.RANCHER_API_TOKEN = os.environ.get("RANCHER_API_TOKEN", "")
        self.RANCHER_API_URL = os.environ.get("RANCHER_API_URL", "")
        self.RANCHER_CLUSTER_ID = os.environ.get("RANCHER_CLUSTER_ID", "")
        self.RANCHER_REPO_NAME = os.environ.get("RANCHER_REPO_NAME", "")

        # Desktop image settings
        self.DESKTOP_IMAGE = os.environ.get(
            "DESKTOP_IMAGE", "cerit.io/desktops/ubuntu-xfce:22.04-user"
        )
