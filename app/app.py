from config.config import Config
from application import create_app

app = create_app(Config)
