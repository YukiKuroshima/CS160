import os
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
from app.models.database import db
from app import create_app
# from app.models import rides_model
from app.models import drives_model
from app.models import users_model
import unittest

app = create_app(config_name=os.getenv('APP_SETTINGS'))
migrate = Migrate(app, db)
manager = Manager(app)

manager.add_command('db', MigrateCommand)


app = create_app(config_name=os.getenv('APP_SETTINGS'))
migrate = Migrate(app, db)

manager = Manager(app)
manager.add_command('db', MigrateCommand)


# define our command for testing called "test"
# Usage: python manage.py test
@manager.command
def test():
    """Runs the unit tests without test coverage."""
    tests = unittest.TestLoader().discover('./tests', pattern='test*.py')
    result = unittest.TextTestRunner(verbosity=2).run(tests)
    if result.wasSuccessful():
        return 0
    return 1

if __name__ == '__main__':
    manager.run()
