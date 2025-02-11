from config.config import Config
from __init__ import create_app

app = create_app(Config)

if __name__ == '__main__':
    app.run()
