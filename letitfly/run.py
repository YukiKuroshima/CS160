import os

from app import create_app

# Getting configuration from .env file
config_name = os.getenv('APP_SETTINGS')  # config_name = "development"
app = create_app(config_name)

if __name__ == '__main__':
    # Heroku needs this
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
