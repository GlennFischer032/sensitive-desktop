# config.py

import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your_secret_key')
    
    # MySQL Database settings
    MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
    MYSQL_PORT = os.environ.get('MYSQL_PORT', '3306')
    MYSQL_DATABASE = os.environ.get('MYSQL_DATABASE', 'desktop_manager')
    MYSQL_USER = os.environ.get('MYSQL_USER', 'guacamole_user')
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', '')
    
    # SQLAlchemy URL construction for MySQL
    DATABASE_URL = os.environ.get('DATABASE_URL', 
        f'mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DATABASE}'
    )

    # Guacamole API settings
    GUACAMOLE_API_URL = os.environ.get('GUACAMOLE_API_URL', 'http://localhost:8080/guacamole/api')
    GUACAMOLE_USERNAME = os.environ.get('GUACAMOLE_USERNAME', 'newadmin')  # Replace with your Guacamole admin username
    GUACAMOLE_PASSWORD = os.environ.get('GUACAMOLE_PASSWORD', 'test')      # Replace with your Guacamole admin password

    # Other settings
    NAMESPACE = os.environ.get('NAMESPACE', 'fischer-ns')
    VALUES_FILE_PATH = os.environ.get('VALUES_FILE_PATH', './desktop/values.yaml')
    TEMP_VALUES_FILE_PATH = os.environ.get('TEMP_VALUES_FILE_PATH', './temp_values.yaml')

    # Admin user credentials
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')

    # Rancher API settings
    RANCHER_API_TOKEN = os.environ.get('RANCHER_API_TOKEN', 'token-z5fcl:bctltsf8v4vchr5qln4rsbbqtg6sv2fq5vfg2h8tplbbzw6h74xwvx')
    RANCHER_API_URL = os.environ.get('RANCHER_API_URL', 'https://rancher.cloud.e-infra.cz')
    RANCHER_CLUSTER_ID = os.environ.get('RANCHER_CLUSTER_ID', 'c-m-qvndqhf6')
    RANCHER_REPO_NAME = os.environ.get('RANCHER_REPO_NAME', 'cerit-sc')

    # Desktop image settings
    DESKTOP_IMAGE = os.environ.get('DESKTOP_IMAGE', 'cerit.io/desktops/ubuntu-xfce:22.04-user')
