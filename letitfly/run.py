import os

from app import create_app

# Getting configuration from .env file
config_name = os.getenv('APP_SETTINGS')  # config_name = "development"
app = create_app(config_name)

if __name__ == '__main__':
    app.run()
