# This scripts handles all db migrations such as upgrading the db and so on
from app import db, create_app
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager, Shell
from app.models import User

app = create_app()

migrate = Migrate(app, db)
manager = Manager(app)
manager.add_command('db', MigrateCommand)

def make_shell_context():
    return dict(app=app, db=db, User=User)
manager.add_command('Shell', Shell(make_context=make_shell_context()))
manager.add_command('db', MigrateCommand)


if __name__ == '__main__':
    manager.run()